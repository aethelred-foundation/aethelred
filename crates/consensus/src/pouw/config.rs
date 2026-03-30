//! Proof-of-Useful-Work Configuration
//!
//! Enterprise-grade configuration parameters for the PoUW consensus mechanism.
//! PoUW extends traditional PoS by weighting validator selection based on
//! verified AI computations that provide real-world utility.
//!
//! # Economic Design Philosophy
//!
//! PoUW implements a **Productivity-Biased** economic model where:
//! - Validators earn rewards proportional to verified AI work
//! - Useful Work Units (UWU) replace generic compute metrics
//! - Utility Categories classify work by real-world impact
//! - Anti-whale mechanisms prevent capital-only domination
//!
//! # Configuration Categories
//!
//! 1. **Timing**: Slot/epoch parameters
//! 2. **Staking**: Minimum stake, validator limits
//! 3. **Useful Work Scoring**: UWU calculation, multipliers, decay
//! 4. **Utility Categories**: Work classification and weighting
//! 5. **VRF**: Verifiable randomness parameters
//! 6. **Finality**: Justification and finalization thresholds
//! 7. **Slashing**: Penalties for misbehavior
//! 8. **Rewards**: Block rewards and distribution

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// UTILITY CATEGORIES
// =============================================================================

/// Utility Category for classifying AI/ML work by real-world impact
///
/// Different categories receive different reward multipliers based on
/// their societal and economic utility. This encourages validators to
/// prioritize high-impact computations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[derive(Default)]
pub enum UtilityCategory {
    /// General computation (baseline)
    #[default]
    General = 0,

    /// Financial services (credit scoring, risk assessment, fraud detection)
    /// - High societal impact: Enables access to credit for underserved populations
    /// - High regulatory scrutiny: Requires auditability
    Financial = 1,

    /// Medical/Healthcare AI (diagnostics, drug discovery, patient care)
    /// - Highest societal impact: Directly affects human health
    /// - Maximum regulatory requirements: HIPAA, FDA compliance
    Medical = 2,

    /// Scientific research (climate modeling, materials science, genomics)
    /// - Long-term societal benefit
    /// - Supports knowledge advancement
    Scientific = 3,

    /// Infrastructure/Security (network optimization, cybersecurity)
    /// - Enables other economic activity
    /// - Critical for digital economy
    Infrastructure = 4,

    /// Environmental (carbon tracking, sustainability, resource optimization)
    /// - Supports ESG initiatives
    /// - Growing regulatory relevance
    Environmental = 5,

    /// Education/Training (model training, educational AI)
    /// - Human capital development
    /// - Democratizes access to knowledge
    Education = 6,

    /// Entertainment/Creative (content generation, gaming)
    /// - Lower priority but high volume
    /// - Baseline utility
    Entertainment = 7,
}

impl UtilityCategory {
    /// Get the default reward multiplier for this category (basis points)
    /// 10000 = 1.0x, 15000 = 1.5x, 20000 = 2.0x
    pub fn default_multiplier_bps(&self) -> u64 {
        match self {
            UtilityCategory::General => 10000,        // 1.0x baseline
            UtilityCategory::Financial => 15000,      // 1.5x (high auditability need)
            UtilityCategory::Medical => 20000,        // 2.0x (highest societal impact)
            UtilityCategory::Scientific => 17500,     // 1.75x (knowledge advancement)
            UtilityCategory::Infrastructure => 14000, // 1.4x (enables other activity)
            UtilityCategory::Environmental => 16000,  // 1.6x (ESG importance)
            UtilityCategory::Education => 13000,      // 1.3x (human capital)
            UtilityCategory::Entertainment => 10000,  // 1.0x baseline
        }
    }

    /// Get the verification strictness level (0-100)
    /// Higher = more rigorous proof requirements
    pub fn verification_strictness(&self) -> u8 {
        match self {
            UtilityCategory::General => 50,
            UtilityCategory::Financial => 90,
            UtilityCategory::Medical => 100, // Maximum strictness
            UtilityCategory::Scientific => 80,
            UtilityCategory::Infrastructure => 70,
            UtilityCategory::Environmental => 75,
            UtilityCategory::Education => 60,
            UtilityCategory::Entertainment => 40,
        }
    }

    /// Check if this category requires TEE attestation
    pub fn requires_tee(&self) -> bool {
        matches!(
            self,
            UtilityCategory::Financial | UtilityCategory::Medical | UtilityCategory::Infrastructure
        )
    }

    /// Check if this category supports zkML proofs
    pub fn supports_zkml(&self) -> bool {
        true // All categories can use zkML
    }

    /// Get the regulatory compliance level required
    pub fn compliance_level(&self) -> ComplianceLevel {
        match self {
            UtilityCategory::Medical => ComplianceLevel::Maximum,
            UtilityCategory::Financial => ComplianceLevel::High,
            UtilityCategory::Infrastructure => ComplianceLevel::High,
            UtilityCategory::Environmental => ComplianceLevel::Medium,
            UtilityCategory::Scientific => ComplianceLevel::Medium,
            UtilityCategory::Education => ComplianceLevel::Standard,
            UtilityCategory::General => ComplianceLevel::Standard,
            UtilityCategory::Entertainment => ComplianceLevel::Minimal,
        }
    }

    /// Parse from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(UtilityCategory::General),
            1 => Some(UtilityCategory::Financial),
            2 => Some(UtilityCategory::Medical),
            3 => Some(UtilityCategory::Scientific),
            4 => Some(UtilityCategory::Infrastructure),
            5 => Some(UtilityCategory::Environmental),
            6 => Some(UtilityCategory::Education),
            7 => Some(UtilityCategory::Entertainment),
            _ => None,
        }
    }

    /// Get all categories
    pub fn all() -> &'static [UtilityCategory] {
        &[
            UtilityCategory::General,
            UtilityCategory::Financial,
            UtilityCategory::Medical,
            UtilityCategory::Scientific,
            UtilityCategory::Infrastructure,
            UtilityCategory::Environmental,
            UtilityCategory::Education,
            UtilityCategory::Entertainment,
        ]
    }
}

impl std::fmt::Display for UtilityCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UtilityCategory::General => write!(f, "General"),
            UtilityCategory::Financial => write!(f, "Financial"),
            UtilityCategory::Medical => write!(f, "Medical"),
            UtilityCategory::Scientific => write!(f, "Scientific"),
            UtilityCategory::Infrastructure => write!(f, "Infrastructure"),
            UtilityCategory::Environmental => write!(f, "Environmental"),
            UtilityCategory::Education => write!(f, "Education"),
            UtilityCategory::Entertainment => write!(f, "Entertainment"),
        }
    }
}

// =============================================================================
// COMPLIANCE LEVELS
// =============================================================================

/// Compliance level required for different utility categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceLevel {
    /// Minimal compliance (basic KYC only)
    Minimal,
    /// Standard compliance (KYC + basic audit trail)
    Standard,
    /// Medium compliance (KYC + detailed audit + some certifications)
    Medium,
    /// High compliance (full regulatory suite minus medical)
    High,
    /// Maximum compliance (all certifications, full audit trail)
    Maximum,
}

impl ComplianceLevel {
    /// Get required certifications for this level
    pub fn required_certifications(&self) -> &'static [&'static str] {
        match self {
            ComplianceLevel::Minimal => &[],
            ComplianceLevel::Standard => &["KYC"],
            ComplianceLevel::Medium => &["KYC", "AML"],
            ComplianceLevel::High => &["KYC", "AML", "SOC2"],
            ComplianceLevel::Maximum => &["KYC", "AML", "SOC2", "HIPAA", "GDPR", "PCI-DSS"],
        }
    }

    /// Get audit retention period in days
    pub fn audit_retention_days(&self) -> u64 {
        match self {
            ComplianceLevel::Minimal => 30,
            ComplianceLevel::Standard => 90,
            ComplianceLevel::Medium => 365,
            ComplianceLevel::High => 365 * 3,
            ComplianceLevel::Maximum => 365 * 7,
        }
    }
}

// =============================================================================
// USEFUL WORK SCORING CONFIGURATION
// =============================================================================

/// Configuration for Useful Work Unit (UWU) calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsefulWorkConfig {
    /// Base UWU per verified inference
    pub base_uwu_per_inference: u64,

    /// UWU scaling factor per complexity unit (basis points)
    pub complexity_scaling_bps: u64,

    /// Maximum UWU per single job (prevents gaming)
    pub max_uwu_per_job: u64,

    /// Minimum complexity for a job to earn UWU
    pub min_complexity_threshold: u64,

    /// Maximum complexity that contributes to UWU (diminishing returns above this)
    pub max_complexity_threshold: u64,

    /// Category multipliers (basis points, 10000 = 1.0x)
    pub category_multipliers: HashMap<UtilityCategory, u64>,

    /// Verification method multipliers (basis points)
    pub verification_multipliers: VerificationMultipliers,

    /// Time decay configuration
    pub decay_config: DecayConfig,

    /// Anti-gaming configuration
    pub anti_gaming: AntiGamingConfig,
}

impl Default for UsefulWorkConfig {
    fn default() -> Self {
        let mut category_multipliers = HashMap::new();
        for category in UtilityCategory::all() {
            category_multipliers.insert(*category, category.default_multiplier_bps());
        }

        Self {
            base_uwu_per_inference: 100,
            complexity_scaling_bps: 100, // 1% per complexity unit
            max_uwu_per_job: 1_000_000,
            min_complexity_threshold: 1000,
            max_complexity_threshold: 10_000_000,
            category_multipliers,
            verification_multipliers: VerificationMultipliers::default(),
            decay_config: DecayConfig::default(),
            anti_gaming: AntiGamingConfig::default(),
        }
    }
}

/// Multipliers for different verification methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMultipliers {
    /// TEE attestation only (basis points)
    pub tee_only_bps: u64,
    /// zkML proof only (basis points)
    pub zkml_only_bps: u64,
    /// Hybrid (TEE + zkML) (basis points)
    pub hybrid_bps: u64,
    /// Re-execution verification (basis points)
    pub reexecution_bps: u64,
    /// AI proof verification (new method) (basis points)
    pub ai_proof_bps: u64,
}

impl Default for VerificationMultipliers {
    fn default() -> Self {
        Self {
            tee_only_bps: 10000,   // 1.0x baseline
            zkml_only_bps: 15000,  // 1.5x (stronger cryptographic guarantees)
            hybrid_bps: 20000,     // 2.0x (maximum assurance)
            reexecution_bps: 8000, // 0.8x (less efficient)
            ai_proof_bps: 17500,   // 1.75x (emerging standard)
        }
    }
}

/// Time decay configuration for Useful Work Scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Decay factor per epoch (0.0-1.0)
    /// Applied as: new_score = old_score * decay_factor
    pub epoch_decay_factor: f64,

    /// Window size in epochs for rolling score calculation
    pub rolling_window_epochs: u64,

    /// Minimum score before complete decay
    pub minimum_score: u64,

    /// Decay starts after this many epochs of inactivity
    pub inactivity_grace_epochs: u64,

    /// Accelerated decay factor for inactive validators
    pub inactive_decay_factor: f64,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            epoch_decay_factor: 0.95,  // 5% decay per epoch
            rolling_window_epochs: 30, // ~30 day window
            minimum_score: 1,
            inactivity_grace_epochs: 3,  // 3 epoch grace period
            inactive_decay_factor: 0.80, // 20% decay when inactive
        }
    }
}

/// Anti-gaming configuration to prevent score manipulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiGamingConfig {
    /// Maximum UWU increase per epoch (prevents sudden spikes)
    pub max_epoch_increase_pct: u64,

    /// Minimum unique job sources required per epoch
    pub min_unique_sources: u64,

    /// Suspicious activity threshold (ratio of max to avg jobs)
    pub suspicious_ratio_threshold: f64,

    /// Cooldown epochs after suspicious activity detection
    pub suspicious_cooldown_epochs: u64,

    /// Enable Sybil resistance checks
    pub enable_sybil_checks: bool,

    /// Maximum jobs from single requester per epoch
    pub max_jobs_per_requester: u64,
}

impl Default for AntiGamingConfig {
    fn default() -> Self {
        Self {
            max_epoch_increase_pct: 200,      // Max 200% increase per epoch
            min_unique_sources: 3,            // At least 3 different requesters
            suspicious_ratio_threshold: 10.0, // 10x average is suspicious
            suspicious_cooldown_epochs: 5,
            enable_sybil_checks: true,
            max_jobs_per_requester: 1000,
        }
    }
}

// =============================================================================
// MAIN POUW CONFIGURATION
// =============================================================================

/// Proof-of-Useful-Work configuration
///
/// Comprehensive configuration for the PoUW consensus mechanism,
/// designed for enterprise-grade AI verification networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUWConfig {
    // =========================================================================
    // TIMING
    // =========================================================================
    /// Slot duration in milliseconds
    pub slot_duration_ms: u64,

    /// Slots per epoch
    pub slots_per_epoch: u64,

    /// Block production timeout in milliseconds
    pub block_timeout_ms: u64,

    /// Maximum clock drift allowed (seconds)
    pub max_clock_drift_secs: u64,

    // =========================================================================
    // STAKING
    // =========================================================================
    /// Minimum stake to be eligible for leader election
    pub min_stake: u128,

    /// Maximum validators in active set
    pub max_validators: u32,

    /// Unbonding period in epochs
    pub unbonding_epochs: u64,

    /// Minimum self-delegation ratio (basis points)
    pub min_self_delegation_bps: u64,

    // =========================================================================
    // USEFUL WORK SCORING
    // =========================================================================
    /// Maximum Useful Work Multiplier (caps compute advantage)
    pub max_useful_work_multiplier: f64,

    /// Useful Work Score configuration
    pub useful_work_config: UsefulWorkConfig,

    /// Maximum Useful Work Score (prevents overflow)
    pub max_useful_work_score: u64,

    // =========================================================================
    // VRF
    // =========================================================================
    /// Chain ID for VRF domain separation
    pub chain_id: u64,

    /// Enable VRF key rotation per epoch
    pub enable_key_rotation: bool,

    /// VRF output bias protection threshold
    pub vrf_bias_threshold: u64,

    // =========================================================================
    // FINALITY
    // =========================================================================
    /// Percentage of stake required for justification (basis points)
    pub justification_threshold_bps: u64,

    /// Percentage of stake required for finalization (basis points)
    pub finalization_threshold_bps: u64,

    /// Epochs to look back for finalization
    pub finalization_lookback_epochs: u64,

    /// Enable optimistic fast finality
    pub enable_fast_finality: bool,

    // =========================================================================
    // SLASHING
    // =========================================================================
    /// Slash percentage for double proposal (basis points)
    pub double_proposal_slash_bps: u64,

    /// Slash percentage for conflicting finality vote (basis points)
    pub conflicting_finality_slash_bps: u64,

    /// Slash percentage for invalid proof submission (basis points)
    pub invalid_proof_slash_bps: u64,

    /// Slash percentage for SLA violation (basis points)
    pub sla_violation_slash_bps: u64,

    /// Jail duration in slots for minor infractions
    pub minor_jail_duration: u64,

    /// Jail duration in slots for major infractions
    pub major_jail_duration: u64,

    // =========================================================================
    // REWARDS
    // =========================================================================
    /// Base block reward
    pub base_block_reward: u128,

    /// Useful Work reward per UWU
    pub reward_per_uwu: u128,

    /// Proposer reward percentage (basis points)
    pub proposer_reward_bps: u64,

    /// Attestor reward percentage (basis points)
    pub attestor_reward_bps: u64,

    /// Useful Work verifier reward percentage (basis points)
    pub verifier_reward_bps: u64,

    // =========================================================================
    // VERIFICATION
    // =========================================================================
    /// Minimum validators required for re-execution verification
    pub min_reexecution_validators: u32,

    /// Enable AI proof verification
    pub enable_ai_proof_verification: bool,

    /// AI proof confidence threshold (basis points, 9500 = 95%)
    pub ai_proof_confidence_threshold_bps: u64,

    /// Maximum proof verification time (milliseconds)
    pub max_verification_time_ms: u64,
}

impl Default for PoUWConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl PoUWConfig {
    /// Mainnet configuration
    ///
    /// Production parameters for the Aethelred mainnet.
    /// Designed for maximum security and economic stability.
    pub fn mainnet() -> Self {
        Self {
            // Timing: ~6 second slots, ~30 day epochs
            slot_duration_ms: 6000,
            slots_per_epoch: 432_000,
            block_timeout_ms: 4000,
            max_clock_drift_secs: 30,

            // Staking
            min_stake: 1_000_000_000_000_000_000, // 1000 tokens (18 decimals)
            max_validators: 200,
            unbonding_epochs: 2,           // ~60 days
            min_self_delegation_bps: 1000, // 10% minimum self-delegation

            // Useful Work scoring
            max_useful_work_multiplier: 5.0,
            useful_work_config: UsefulWorkConfig::default(),
            max_useful_work_score: u64::MAX / 2, // Prevent overflow

            // VRF
            chain_id: 1,
            enable_key_rotation: true,
            vrf_bias_threshold: 100,

            // Finality: 67% and 80%
            justification_threshold_bps: 6667,
            finalization_threshold_bps: 8000,
            finalization_lookback_epochs: 2,
            enable_fast_finality: true,

            // Slashing
            double_proposal_slash_bps: 500,       // 5%
            conflicting_finality_slash_bps: 2000, // 20%
            invalid_proof_slash_bps: 1000,        // 10%
            sla_violation_slash_bps: 300,         // 3%
            minor_jail_duration: 14400,           // ~24 hours
            major_jail_duration: 432_000,         // ~30 days

            // Rewards
            base_block_reward: 1_000_000_000_000_000_000, // 1 token
            reward_per_uwu: 1_000_000,                    // Small per-UWU
            proposer_reward_bps: 2500,                    // 25%
            attestor_reward_bps: 5000,                    // 50%
            verifier_reward_bps: 2500,                    // 25%

            // Verification
            min_reexecution_validators: 3,
            enable_ai_proof_verification: true,
            ai_proof_confidence_threshold_bps: 9500, // 95%
            max_verification_time_ms: 30000,         // 30 seconds
        }
    }

    /// Testnet configuration (faster, lower thresholds)
    pub fn testnet() -> Self {
        Self {
            // Faster timing: 3 second slots, ~3 day epochs
            slot_duration_ms: 3000,
            slots_per_epoch: 86_400,
            block_timeout_ms: 2000,
            max_clock_drift_secs: 60,

            // Lower staking requirements
            min_stake: 1_000_000_000_000, // 1 token
            max_validators: 100,
            unbonding_epochs: 1,
            min_self_delegation_bps: 500, // 5%

            // Same useful work scoring
            max_useful_work_multiplier: 5.0,
            useful_work_config: {
                let mut config = UsefulWorkConfig::default();
                config.anti_gaming.enable_sybil_checks = false; // Relaxed for testing
                config
            },
            max_useful_work_score: u64::MAX / 2,

            // VRF
            chain_id: 2,
            enable_key_rotation: false,
            vrf_bias_threshold: 50,

            // Lower finality thresholds
            justification_threshold_bps: 5000, // 50%
            finalization_threshold_bps: 6667,  // 67%
            finalization_lookback_epochs: 1,
            enable_fast_finality: true,

            // Lower slashing
            double_proposal_slash_bps: 100,
            conflicting_finality_slash_bps: 500,
            invalid_proof_slash_bps: 200,
            sla_violation_slash_bps: 50,
            minor_jail_duration: 1000,
            major_jail_duration: 10_000,

            // Higher rewards for testing
            base_block_reward: 10_000_000_000_000_000_000,
            reward_per_uwu: 10_000_000,
            proposer_reward_bps: 2500,
            attestor_reward_bps: 5000,
            verifier_reward_bps: 2500,

            // Verification
            min_reexecution_validators: 2,
            enable_ai_proof_verification: true,
            ai_proof_confidence_threshold_bps: 9000, // 90%
            max_verification_time_ms: 60000,
        }
    }

    /// Development configuration (instant finality)
    pub fn devnet() -> Self {
        Self {
            // Very fast: 1 second slots, 100 slot epochs
            slot_duration_ms: 1000,
            slots_per_epoch: 100,
            block_timeout_ms: 800,
            max_clock_drift_secs: 120,

            // Minimal staking
            min_stake: 1,
            max_validators: 10,
            unbonding_epochs: 0,
            min_self_delegation_bps: 0,

            // Relaxed useful work config
            max_useful_work_multiplier: 5.0,
            useful_work_config: {
                let mut config = UsefulWorkConfig::default();
                config.decay_config.epoch_decay_factor = 1.0; // No decay
                config.anti_gaming.enable_sybil_checks = false;
                config.min_complexity_threshold = 0;
                config
            },
            max_useful_work_score: u64::MAX,

            // VRF
            chain_id: 999,
            enable_key_rotation: false,
            vrf_bias_threshold: 0,

            // Instant finality
            justification_threshold_bps: 1,
            finalization_threshold_bps: 1,
            finalization_lookback_epochs: 0,
            enable_fast_finality: true,

            // No slashing
            double_proposal_slash_bps: 0,
            conflicting_finality_slash_bps: 0,
            invalid_proof_slash_bps: 0,
            sla_violation_slash_bps: 0,
            minor_jail_duration: 0,
            major_jail_duration: 0,

            // High rewards
            base_block_reward: 1_000_000_000_000_000_000_000,
            reward_per_uwu: 1_000_000_000,
            proposer_reward_bps: 3333,
            attestor_reward_bps: 3333,
            verifier_reward_bps: 3334,

            // Verification
            min_reexecution_validators: 1,
            enable_ai_proof_verification: true,
            ai_proof_confidence_threshold_bps: 5000, // 50%
            max_verification_time_ms: 120000,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Timing
        if self.slot_duration_ms == 0 {
            return Err("Slot duration must be > 0".into());
        }
        if self.slots_per_epoch == 0 {
            return Err("Slots per epoch must be > 0".into());
        }
        if self.block_timeout_ms >= self.slot_duration_ms {
            return Err("Block timeout must be < slot duration".into());
        }

        // Useful Work
        if self.max_useful_work_multiplier <= 1.0 {
            return Err("Max useful work multiplier must be > 1.0".into());
        }

        let decay = self.useful_work_config.decay_config.epoch_decay_factor;
        if decay <= 0.0 || decay > 1.0 {
            return Err("Useful work decay factor must be in (0.0, 1.0]".into());
        }

        // Finality
        if self.justification_threshold_bps > 10000 {
            return Err("Justification threshold cannot exceed 100%".into());
        }
        if self.finalization_threshold_bps > 10000 {
            return Err("Finalization threshold cannot exceed 100%".into());
        }
        if self.finalization_threshold_bps < self.justification_threshold_bps {
            return Err("Finalization threshold must be >= justification threshold".into());
        }

        // Slashing
        if self.double_proposal_slash_bps > 10000 {
            return Err("Slash percentage cannot exceed 100%".into());
        }

        // Rewards
        let total_reward_bps =
            self.proposer_reward_bps + self.attestor_reward_bps + self.verifier_reward_bps;
        if total_reward_bps != 10000 {
            return Err(format!(
                "Proposer + attestor + verifier rewards must equal 100% (got {}%)",
                total_reward_bps / 100
            ));
        }

        // Verification
        if self.ai_proof_confidence_threshold_bps > 10000 {
            return Err("AI proof confidence threshold cannot exceed 100%".into());
        }

        Ok(())
    }

    /// Get epoch for a slot
    pub fn epoch_for_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    /// Get first slot of an epoch
    pub fn first_slot_of_epoch(&self, epoch: u64) -> u64 {
        epoch * self.slots_per_epoch
    }

    /// Check if slot is an epoch boundary
    pub fn is_epoch_boundary(&self, slot: u64) -> bool {
        slot.is_multiple_of(self.slots_per_epoch)
    }

    /// Get category multiplier (basis points)
    pub fn category_multiplier(&self, category: UtilityCategory) -> u64 {
        self.useful_work_config
            .category_multipliers
            .get(&category)
            .copied()
            .unwrap_or(category.default_multiplier_bps())
    }

    /// Calculate Useful Work Units for a job
    pub fn calculate_uwu(
        &self,
        complexity: u64,
        category: UtilityCategory,
        verification_method: VerificationMethod,
    ) -> u64 {
        let config = &self.useful_work_config;

        // Check minimum threshold
        if complexity < config.min_complexity_threshold {
            return 0;
        }

        // Cap complexity at maximum
        let effective_complexity = complexity.min(config.max_complexity_threshold);

        // Base UWU
        let base = config.base_uwu_per_inference;

        // Complexity scaling (with diminishing returns)
        let complexity_bonus =
            (effective_complexity as u128 * config.complexity_scaling_bps as u128 / 10000) as u64;

        // Category multiplier
        let category_mult = self.category_multiplier(category);

        // Verification method multiplier
        let verification_mult = match verification_method {
            VerificationMethod::TeeAttestation => config.verification_multipliers.tee_only_bps,
            VerificationMethod::ZkProof => config.verification_multipliers.zkml_only_bps,
            VerificationMethod::Hybrid => config.verification_multipliers.hybrid_bps,
            VerificationMethod::ReExecution => config.verification_multipliers.reexecution_bps,
            VerificationMethod::AiProof => config.verification_multipliers.ai_proof_bps,
        };

        // Calculate final UWU
        let raw_uwu = base.saturating_add(complexity_bonus);
        let with_category = (raw_uwu as u128 * category_mult as u128 / 10000) as u64;
        let final_uwu = (with_category as u128 * verification_mult as u128 / 10000) as u64;

        // Cap at maximum
        final_uwu.min(config.max_uwu_per_job)
    }
}

/// Verification method for AI computations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum VerificationMethod {
    /// TEE attestation only
    #[default]
    TeeAttestation,
    /// Zero-knowledge proof
    ZkProof,
    /// Hybrid (TEE + ZK)
    Hybrid,
    /// Re-execution by multiple validators
    ReExecution,
    /// AI-based proof verification
    AiProof,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = PoUWConfig::mainnet();
        assert!(config.validate().is_ok());

        let config = PoUWConfig::testnet();
        assert!(config.validate().is_ok());

        let config = PoUWConfig::devnet();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let mut config = PoUWConfig::mainnet();

        // Invalid timeout
        config.block_timeout_ms = 10000;
        assert!(config.validate().is_err());
        config.block_timeout_ms = 4000;

        // Invalid multiplier
        config.max_useful_work_multiplier = 0.5;
        assert!(config.validate().is_err());
        config.max_useful_work_multiplier = 5.0;

        // Invalid decay
        config.useful_work_config.decay_config.epoch_decay_factor = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_epoch_calculation() {
        let config = PoUWConfig {
            slots_per_epoch: 100,
            ..PoUWConfig::devnet()
        };

        assert_eq!(config.epoch_for_slot(0), 0);
        assert_eq!(config.epoch_for_slot(99), 0);
        assert_eq!(config.epoch_for_slot(100), 1);
        assert_eq!(config.epoch_for_slot(250), 2);

        assert!(config.is_epoch_boundary(0));
        assert!(config.is_epoch_boundary(100));
        assert!(!config.is_epoch_boundary(50));
    }

    #[test]
    fn test_utility_categories() {
        // Medical should have highest multiplier
        assert!(
            UtilityCategory::Medical.default_multiplier_bps()
                > UtilityCategory::Financial.default_multiplier_bps()
        );

        // Medical and Financial require TEE
        assert!(UtilityCategory::Medical.requires_tee());
        assert!(UtilityCategory::Financial.requires_tee());
        assert!(!UtilityCategory::Entertainment.requires_tee());

        // Medical requires maximum compliance
        assert_eq!(
            UtilityCategory::Medical.compliance_level(),
            ComplianceLevel::Maximum
        );
    }

    #[test]
    fn test_uwu_calculation() {
        let config = PoUWConfig::mainnet();

        // Below threshold = 0 UWU
        let uwu = config.calculate_uwu(
            100,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        assert_eq!(uwu, 0);

        // Above threshold = positive UWU
        let uwu = config.calculate_uwu(
            10000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        assert!(uwu > 0);

        // Medical should give more than General
        let uwu_general = config.calculate_uwu(
            10000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let uwu_medical = config.calculate_uwu(
            10000,
            UtilityCategory::Medical,
            VerificationMethod::TeeAttestation,
        );
        assert!(uwu_medical > uwu_general);

        // Hybrid verification should give more than TEE only
        let uwu_tee = config.calculate_uwu(
            10000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let uwu_hybrid =
            config.calculate_uwu(10000, UtilityCategory::General, VerificationMethod::Hybrid);
        assert!(uwu_hybrid > uwu_tee);
    }

    #[test]
    fn test_verification_multipliers() {
        let multipliers = VerificationMultipliers::default();

        // Hybrid should be highest
        assert!(multipliers.hybrid_bps > multipliers.zkml_only_bps);
        assert!(multipliers.zkml_only_bps > multipliers.tee_only_bps);
        assert!(multipliers.tee_only_bps > multipliers.reexecution_bps);
    }

    #[test]
    fn test_compliance_levels() {
        // Maximum should require most certifications
        assert!(
            ComplianceLevel::Maximum.required_certifications().len()
                > ComplianceLevel::High.required_certifications().len()
        );

        // Maximum should have longest retention
        assert!(
            ComplianceLevel::Maximum.audit_retention_days()
                > ComplianceLevel::Minimal.audit_retention_days()
        );
    }

    // =========================================================================
    // validate() - individual error branches
    // =========================================================================

    #[test]
    fn test_validate_slot_duration_zero() {
        let mut config = PoUWConfig::mainnet();
        config.slot_duration_ms = 0;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Slot duration must be > 0"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_slots_per_epoch_zero() {
        let mut config = PoUWConfig::mainnet();
        config.slots_per_epoch = 0;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Slots per epoch must be > 0"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_justification_threshold_exceeds_10000() {
        let mut config = PoUWConfig::mainnet();
        config.justification_threshold_bps = 10001;
        // finalization must also stay >= justification; bump it too so we
        // hit only the justification check.
        config.finalization_threshold_bps = 10001;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Justification threshold cannot exceed 100%"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_finalization_threshold_exceeds_10000() {
        let mut config = PoUWConfig::mainnet();
        // Keep justification valid, push finalization over 100 %.
        config.justification_threshold_bps = 6667;
        config.finalization_threshold_bps = 10001;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Finalization threshold cannot exceed 100%"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_finalization_less_than_justification() {
        let mut config = PoUWConfig::mainnet();
        config.justification_threshold_bps = 8000;
        config.finalization_threshold_bps = 6000; // lower than justification
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Finalization threshold must be >= justification threshold"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_double_proposal_slash_exceeds_10000() {
        let mut config = PoUWConfig::mainnet();
        config.double_proposal_slash_bps = 10001;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Slash percentage cannot exceed 100%"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_reward_bps_not_summing_to_10000() {
        let mut config = PoUWConfig::mainnet();
        // Shift some BPS so the sum is != 10000.
        config.proposer_reward_bps = 3000; // was 2500; total becomes 10500
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Proposer + attestor + verifier rewards must equal 100%"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_ai_proof_confidence_exceeds_10000() {
        let mut config = PoUWConfig::mainnet();
        config.ai_proof_confidence_threshold_bps = 10001;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("AI proof confidence threshold cannot exceed 100%"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_validate_decay_factor_zero() {
        let mut config = PoUWConfig::mainnet();
        config.useful_work_config.decay_config.epoch_decay_factor = 0.0;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("Useful work decay factor must be in (0.0, 1.0]"),
            "unexpected: {err}"
        );
    }

    // =========================================================================
    // UtilityCategory::from_u8
    // =========================================================================

    #[test]
    fn test_utility_category_from_u8_all_valid() {
        assert_eq!(UtilityCategory::from_u8(0), Some(UtilityCategory::General));
        assert_eq!(
            UtilityCategory::from_u8(1),
            Some(UtilityCategory::Financial)
        );
        assert_eq!(UtilityCategory::from_u8(2), Some(UtilityCategory::Medical));
        assert_eq!(
            UtilityCategory::from_u8(3),
            Some(UtilityCategory::Scientific)
        );
        assert_eq!(
            UtilityCategory::from_u8(4),
            Some(UtilityCategory::Infrastructure)
        );
        assert_eq!(
            UtilityCategory::from_u8(5),
            Some(UtilityCategory::Environmental)
        );
        assert_eq!(
            UtilityCategory::from_u8(6),
            Some(UtilityCategory::Education)
        );
        assert_eq!(
            UtilityCategory::from_u8(7),
            Some(UtilityCategory::Entertainment)
        );
    }

    #[test]
    fn test_utility_category_from_u8_invalid() {
        assert_eq!(UtilityCategory::from_u8(8), None);
        assert_eq!(UtilityCategory::from_u8(255), None);
    }

    // =========================================================================
    // UtilityCategory::Display
    // =========================================================================

    #[test]
    fn test_utility_category_display() {
        assert_eq!(format!("{}", UtilityCategory::General), "General");
        assert_eq!(format!("{}", UtilityCategory::Financial), "Financial");
        assert_eq!(format!("{}", UtilityCategory::Medical), "Medical");
        assert_eq!(format!("{}", UtilityCategory::Scientific), "Scientific");
        assert_eq!(
            format!("{}", UtilityCategory::Infrastructure),
            "Infrastructure"
        );
        assert_eq!(
            format!("{}", UtilityCategory::Environmental),
            "Environmental"
        );
        assert_eq!(format!("{}", UtilityCategory::Education), "Education");
        assert_eq!(
            format!("{}", UtilityCategory::Entertainment),
            "Entertainment"
        );
    }

    // =========================================================================
    // UtilityCategory::Default
    // =========================================================================

    #[test]
    fn test_utility_category_default_is_general() {
        assert_eq!(UtilityCategory::default(), UtilityCategory::General);
    }

    // =========================================================================
    // UtilityCategory::verification_strictness
    // =========================================================================

    #[test]
    fn test_utility_category_verification_strictness() {
        assert_eq!(UtilityCategory::General.verification_strictness(), 50);
        assert_eq!(UtilityCategory::Financial.verification_strictness(), 90);
        assert_eq!(UtilityCategory::Medical.verification_strictness(), 100);
        assert_eq!(UtilityCategory::Scientific.verification_strictness(), 80);
        assert_eq!(
            UtilityCategory::Infrastructure.verification_strictness(),
            70
        );
        assert_eq!(UtilityCategory::Environmental.verification_strictness(), 75);
        assert_eq!(UtilityCategory::Education.verification_strictness(), 60);
        assert_eq!(UtilityCategory::Entertainment.verification_strictness(), 40);

        // Medical must be the most strict of all.
        assert_eq!(
            UtilityCategory::all()
                .iter()
                .map(|c| c.verification_strictness())
                .max()
                .unwrap(),
            100
        );
    }

    // =========================================================================
    // UtilityCategory::supports_zkml
    // =========================================================================

    #[test]
    fn test_all_categories_support_zkml() {
        for category in UtilityCategory::all() {
            assert!(category.supports_zkml(), "{category} should support zkML");
        }
    }

    // =========================================================================
    // UtilityCategory::all
    // =========================================================================

    #[test]
    fn test_utility_category_all_returns_eight_variants() {
        let all = UtilityCategory::all();
        assert_eq!(all.len(), 8);

        // Every from_u8(0..=7) must appear exactly once.
        for i in 0u8..8 {
            let expected = UtilityCategory::from_u8(i).unwrap();
            assert!(
                all.contains(&expected),
                "all() is missing variant for u8={i}"
            );
        }
    }

    // =========================================================================
    // ComplianceLevel - certifications and retention for every variant
    // =========================================================================

    #[test]
    fn test_compliance_level_required_certifications_all_variants() {
        assert_eq!(
            ComplianceLevel::Minimal.required_certifications(),
            &[] as &[&str]
        );
        assert_eq!(
            ComplianceLevel::Standard.required_certifications(),
            &["KYC"]
        );
        assert_eq!(
            ComplianceLevel::Medium.required_certifications(),
            &["KYC", "AML"]
        );
        assert_eq!(
            ComplianceLevel::High.required_certifications(),
            &["KYC", "AML", "SOC2"]
        );
        assert_eq!(
            ComplianceLevel::Maximum.required_certifications(),
            &["KYC", "AML", "SOC2", "HIPAA", "GDPR", "PCI-DSS"]
        );
    }

    #[test]
    fn test_compliance_level_audit_retention_days_all_variants() {
        assert_eq!(ComplianceLevel::Minimal.audit_retention_days(), 30);
        assert_eq!(ComplianceLevel::Standard.audit_retention_days(), 90);
        assert_eq!(ComplianceLevel::Medium.audit_retention_days(), 365);
        assert_eq!(ComplianceLevel::High.audit_retention_days(), 365 * 3);
        assert_eq!(ComplianceLevel::Maximum.audit_retention_days(), 365 * 7);
    }

    // =========================================================================
    // VerificationMethod::Default
    // =========================================================================

    #[test]
    fn test_verification_method_default_is_tee_attestation() {
        assert_eq!(
            VerificationMethod::default(),
            VerificationMethod::TeeAttestation
        );
    }

    // =========================================================================
    // calculate_uwu - additional branches
    // =========================================================================

    #[test]
    fn test_calculate_uwu_complexity_capping() {
        let config = PoUWConfig::mainnet();
        let max_threshold = config.useful_work_config.max_complexity_threshold;

        // UWU at exactly max_threshold and above it should be identical
        // because complexity is capped internally.
        let at_cap = config.calculate_uwu(
            max_threshold,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let above_cap = config.calculate_uwu(
            max_threshold + 1_000_000,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        assert_eq!(
            at_cap, above_cap,
            "UWU must not grow beyond max_complexity_threshold"
        );
    }

    #[test]
    fn test_calculate_uwu_zkproof_multiplier() {
        let config = PoUWConfig::mainnet();
        let complexity = config.useful_work_config.min_complexity_threshold;

        let uwu_tee = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let uwu_zk = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::ZkProof,
        );
        // zkml_only_bps (15000) > tee_only_bps (10000)
        assert!(
            uwu_zk > uwu_tee,
            "ZkProof UWU should exceed TeeAttestation UWU"
        );
    }

    #[test]
    fn test_calculate_uwu_reexecution_multiplier() {
        let config = PoUWConfig::mainnet();
        let complexity = config.useful_work_config.min_complexity_threshold;

        let uwu_tee = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let uwu_reex = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::ReExecution,
        );
        // reexecution_bps (8000) < tee_only_bps (10000)
        assert!(
            uwu_reex < uwu_tee,
            "ReExecution UWU should be less than TeeAttestation UWU"
        );
    }

    #[test]
    fn test_calculate_uwu_aiproof_multiplier() {
        let config = PoUWConfig::mainnet();
        let complexity = config.useful_work_config.min_complexity_threshold;

        let uwu_tee = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::TeeAttestation,
        );
        let uwu_ai = config.calculate_uwu(
            complexity,
            UtilityCategory::General,
            VerificationMethod::AiProof,
        );
        // ai_proof_bps (17500) > tee_only_bps (10000)
        assert!(
            uwu_ai > uwu_tee,
            "AiProof UWU should exceed TeeAttestation UWU"
        );
    }

    #[test]
    fn test_calculate_uwu_max_capping() {
        // Build a config whose max_uwu_per_job is very small so we can force
        // the cap to be hit.
        let mut config = PoUWConfig::mainnet();
        config.useful_work_config.max_uwu_per_job = 1;

        let uwu = config.calculate_uwu(
            config.useful_work_config.min_complexity_threshold,
            UtilityCategory::Medical,
            VerificationMethod::Hybrid,
        );
        assert_eq!(uwu, 1, "UWU must be capped at max_uwu_per_job");
    }

    // =========================================================================
    // UsefulWorkConfig::default
    // =========================================================================

    #[test]
    fn test_useful_work_config_default_values() {
        let cfg = UsefulWorkConfig::default();
        assert_eq!(cfg.base_uwu_per_inference, 100);
        assert_eq!(cfg.complexity_scaling_bps, 100);
        assert_eq!(cfg.max_uwu_per_job, 1_000_000);
        assert_eq!(cfg.min_complexity_threshold, 1000);
        assert_eq!(cfg.max_complexity_threshold, 10_000_000);

        // Every UtilityCategory must have a multiplier entry.
        for category in UtilityCategory::all() {
            assert!(
                cfg.category_multipliers.contains_key(category),
                "Missing multiplier for {category}"
            );
        }
    }

    // =========================================================================
    // DecayConfig::default
    // =========================================================================

    #[test]
    fn test_decay_config_default_values() {
        let cfg = DecayConfig::default();
        assert!((cfg.epoch_decay_factor - 0.95).abs() < f64::EPSILON);
        assert_eq!(cfg.rolling_window_epochs, 30);
        assert_eq!(cfg.minimum_score, 1);
        assert_eq!(cfg.inactivity_grace_epochs, 3);
        assert!((cfg.inactive_decay_factor - 0.80).abs() < f64::EPSILON);
    }

    // =========================================================================
    // AntiGamingConfig::default
    // =========================================================================

    #[test]
    fn test_anti_gaming_config_default_values() {
        let cfg = AntiGamingConfig::default();
        assert_eq!(cfg.max_epoch_increase_pct, 200);
        assert_eq!(cfg.min_unique_sources, 3);
        assert!((cfg.suspicious_ratio_threshold - 10.0).abs() < f64::EPSILON);
        assert_eq!(cfg.suspicious_cooldown_epochs, 5);
        assert!(cfg.enable_sybil_checks);
        assert_eq!(cfg.max_jobs_per_requester, 1000);
    }

    // =========================================================================
    // first_slot_of_epoch
    // =========================================================================

    #[test]
    fn test_first_slot_of_epoch() {
        let config = PoUWConfig {
            slots_per_epoch: 100,
            ..PoUWConfig::devnet()
        };

        assert_eq!(config.first_slot_of_epoch(0), 0);
        assert_eq!(config.first_slot_of_epoch(1), 100);
        assert_eq!(config.first_slot_of_epoch(5), 500);
        assert_eq!(config.first_slot_of_epoch(432), 43200);
    }

    // =========================================================================
    // PoUWConfig::Default delegates to mainnet
    // =========================================================================

    #[test]
    fn test_pouwconfig_default_is_mainnet() {
        let via_default = PoUWConfig::default();
        let mainnet = PoUWConfig::mainnet();

        // Compare a representative set of fields that uniquely identify mainnet.
        assert_eq!(via_default.slot_duration_ms, mainnet.slot_duration_ms);
        assert_eq!(via_default.slots_per_epoch, mainnet.slots_per_epoch);
        assert_eq!(via_default.chain_id, mainnet.chain_id);
        assert_eq!(via_default.min_stake, mainnet.min_stake);
        assert_eq!(via_default.max_validators, mainnet.max_validators);
        assert_eq!(
            via_default.justification_threshold_bps,
            mainnet.justification_threshold_bps
        );
        assert_eq!(
            via_default.finalization_threshold_bps,
            mainnet.finalization_threshold_bps
        );
    }
}
