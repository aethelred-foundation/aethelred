//! # Proof-of-Useful-Work (PoUW) Tokenomics Engine
//!
//! Enterprise-grade economic engine implementing the 4 Strategic Moats for AETHEL:
//!
//! 1. **Compute-Weighted Multiplier** (Anti-Whale): Rewards hardware deployment over passive staking
//! 2. **Regulatory Bonding Curves** (Compliance-as-an-Asset): Insurance bonds for data compliance
//! 3. **Congestion-Squared Deflation**: Exponential burn mechanism during high demand
//! 4. **Sovereignty Premium**: Premium pricing for verified sovereign data access
//!
//! ## Economic Philosophy
//!
//! Traditional PoS is Capital-Biased: the rich get richer by sitting on tokens.
//! AETHEL is Productivity-Biased: rewards flow to infrastructure providers.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────┐
//! │                      PROOF-OF-USEFUL-WORK ECONOMIC ENGINE                            │
//! ├─────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                      │
//! │  ┌─────────────────────────────────────────────────────────────────────────────────┐│
//! │  │                        MOAT 1: COMPUTE-WEIGHTED MULTIPLIER                      ││
//! │  │                                                                                 ││
//! │  │  Traditional:  Reward = Stake × APY                                            ││
//! │  │  AETHEL:       Reward = Stake × APY × (1 + log₁₀(VerifiedComputeOps))         ││
//! │  │                                                                                 ││
//! │  │  Example:                                                                       ││
//! │  │    VC with $10M stake + 0 GPUs      → 1.0x multiplier → $500K/year            ││
//! │  │    Data Center with $1M + 500 H100s → 2.5x multiplier → $125K × 2.5 = $312K   ││
//! │  │                                                                                 ││
//! │  │  Effect: Capital MUST flow into hardware to maximize returns                   ││
//! │  └─────────────────────────────────────────────────────────────────────────────────┘│
//! │                                         │                                            │
//! │                                         ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────────────────────┐│
//! │  │                        MOAT 2: REGULATORY BONDING CURVES                        ││
//! │  │                                                                                 ││
//! │  │  Compliance Bond Required:                                                      ││
//! │  │    GDPR Processing:  5,000 AETHEL bond                                         ││
//! │  │    HIPAA Processing: 10,000 AETHEL bond                                        ││
//! │  │    Financial Data:   15,000 AETHEL bond                                        ││
//! │  │                                                                                 ││
//! │  │  On TEE Attestation Failure (Data Breach):                                     ││
//! │  │    → 80% bond → Victim (Insurance Payout)                                      ││
//! │  │    → 20% bond → Burned (Deflationary Penalty)                                  ││
//! │  │                                                                                 ││
//! │  │  Effect: Nodes become financially accountable for data security                ││
//! │  └─────────────────────────────────────────────────────────────────────────────────┘│
//! │                                         │                                            │
//! │                                         ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────────────────────┐│
//! │  │                      MOAT 3: CONGESTION-SQUARED DEFLATION                       ││
//! │  │                                                                                 ││
//! │  │  Formula: BurnRate = B_min + (B_max - B_min) × (Load/MaxLoad)²                 ││
//! │  │                                                                                 ││
//! │  │  Network Load    Burn Rate    Effect                                           ││
//! │  │  ────────────    ─────────    ──────                                           ││
//! │  │      30%            ~5%       Normal operations                                ││
//! │  │      50%            ~9%       Light congestion                                 ││
//! │  │      70%           ~14%       Moderate congestion                              ││
//! │  │      90%           ~25%       High demand → Aggressive deflation              ││
//! │  │                                                                                 ││
//! │  │  Effect: AI demand spikes create supply shocks benefiting long-term holders   ││
//! │  └─────────────────────────────────────────────────────────────────────────────────┘│
//! │                                         │                                            │
//! │                                         ▼                                            │
//! │  ┌─────────────────────────────────────────────────────────────────────────────────┐│
//! │  │                        MOAT 4: SOVEREIGNTY PREMIUM                              ││
//! │  │                                                                                 ││
//! │  │  Data pricing based on sovereignty and verification:                           ││
//! │  │                                                                                 ││
//! │  │  Data Type                  Multiplier   Example                               ││
//! │  │  ─────────                  ──────────   ───────                               ││
//! │  │  Public Weather Data           1x       0.01 AETHEL                            ││
//! │  │  Verified Financial Data       3x       0.03 AETHEL                            ││
//! │  │  UAE Patient Record (MOHAP)    5x       0.05 AETHEL                            ││
//! │  │  EU GDPR-Verified PII          4x       0.04 AETHEL                            ││
//! │  │                                                                                 ││
//! │  │  Effect: Data providers earn premium for regulatory compliance                 ││
//! │  └─────────────────────────────────────────────────────────────────────────────────┘│
//! │                                                                                      │
//! └─────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Author
//!
//! Aethelred Protocol - Economic Innovation Layer
//!
//! ## License
//!
//! Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::error::{SystemContractError, SystemContractResult as Result};
use super::events::PoUWEvent;
use super::types::{Address, Hash, JobId, TokenAmount};

// =============================================================================
// CONSTANTS
// =============================================================================

/// One AETHEL in wei (10^18)
pub const ONE_AETHEL: TokenAmount = 1_000_000_000_000_000_000;

/// Base APY in basis points (5%)
pub const BASE_APY_BPS: u16 = 500;

/// Maximum compute multiplier (2.5x)
pub const MAX_COMPUTE_MULTIPLIER_BPS: u16 = 2500;

/// Minimum burn rate (5%)
pub const MIN_BURN_RATE_BPS: u16 = 500;

/// Maximum burn rate at full congestion (25%)
pub const MAX_BURN_RATE_BPS: u16 = 2500;

/// Compliance bond victim payout percentage (80%)
pub const COMPLIANCE_VICTIM_PAYOUT_BPS: u16 = 8000;

/// Compliance bond burn percentage (20%)
pub const COMPLIANCE_BURN_BPS: u16 = 2000;

/// Rolling window for compute verification (30 days in seconds)
pub const COMPUTE_VERIFICATION_WINDOW: u64 = 30 * 24 * 60 * 60;

/// Minimum compute ops for bonus tier
pub const COMPUTE_TIER_THRESHOLD: u128 = 1_000_000; // 1M verified ops

/// Attestation failure cooldown (cannot re-stake for 30 days)
pub const ATTESTATION_FAILURE_COOLDOWN: u64 = 30 * 24 * 60 * 60;

// =============================================================================
// COMPLIANCE STANDARDS & BOND REQUIREMENTS
// =============================================================================

/// Compliance standard types for bonding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ComplianceBondType {
    /// GDPR data processing
    GdprProcessing = 1,
    /// HIPAA medical data
    HipaaProcessing = 2,
    /// Financial/Banking data (Basel III)
    FinancialData = 3,
    /// UAE Data Protection Law
    UaeDpl = 4,
    /// Singapore PDPA
    SingaporePdpa = 5,
    /// SOC2 Type II Compliance
    Soc2TypeII = 6,
    /// ISO 27001 Information Security
    Iso27001 = 7,
    /// PCI-DSS Payment Card Data
    PciDss = 8,
}

impl ComplianceBondType {
    /// Get the required bond amount for this compliance type
    pub fn required_bond(&self) -> TokenAmount {
        match self {
            Self::GdprProcessing => 5_000 * ONE_AETHEL,
            Self::HipaaProcessing => 10_000 * ONE_AETHEL,
            Self::FinancialData => 15_000 * ONE_AETHEL,
            Self::UaeDpl => 8_000 * ONE_AETHEL,
            Self::SingaporePdpa => 6_000 * ONE_AETHEL,
            Self::Soc2TypeII => 7_500 * ONE_AETHEL,
            Self::Iso27001 => 5_000 * ONE_AETHEL,
            Self::PciDss => 20_000 * ONE_AETHEL,
        }
    }

    /// Get risk weight for this compliance type (used in multiplier calculations)
    pub fn risk_weight_bps(&self) -> u16 {
        match self {
            Self::GdprProcessing => 100,  // 1x
            Self::HipaaProcessing => 200, // 2x
            Self::FinancialData => 300,   // 3x
            Self::UaeDpl => 150,          // 1.5x
            Self::SingaporePdpa => 120,   // 1.2x
            Self::Soc2TypeII => 110,      // 1.1x
            Self::Iso27001 => 100,        // 1x
            Self::PciDss => 350,          // 3.5x
        }
    }

    /// Get display name
    pub fn name(&self) -> &'static str {
        match self {
            Self::GdprProcessing => "GDPR",
            Self::HipaaProcessing => "HIPAA",
            Self::FinancialData => "FINANCIAL",
            Self::UaeDpl => "UAE_DPL",
            Self::SingaporePdpa => "SG_PDPA",
            Self::Soc2TypeII => "SOC2_TYPE_II",
            Self::Iso27001 => "ISO_27001",
            Self::PciDss => "PCI_DSS",
        }
    }
}

// =============================================================================
// SOVEREIGNTY PREMIUM - DATA JURISDICTION PRICING
// =============================================================================

/// Data sovereignty region for premium pricing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SovereigntyRegion {
    /// Public/International data - no premium
    Public = 0,
    /// European Union (GDPR protected)
    EuropeanUnion = 1,
    /// United Arab Emirates (MOHAP, DHA regulated)
    UnitedArabEmirates = 2,
    /// Singapore (PDPA regulated)
    Singapore = 3,
    /// United States (HIPAA/CCPA regulated)
    UnitedStates = 4,
    /// Switzerland (Banking secrecy)
    Switzerland = 5,
    /// Japan (APPI regulated)
    Japan = 6,
    /// Australia (Privacy Act)
    Australia = 7,
    /// United Kingdom (UK GDPR)
    UnitedKingdom = 8,
    /// China (PIPL regulated)
    China = 9,
}

impl SovereigntyRegion {
    /// Get the sovereignty premium multiplier (in basis points, 100 = 1x)
    pub fn premium_multiplier_bps(&self, verified: bool) -> u16 {
        let base = match self {
            Self::Public => 100,             // 1x (no premium)
            Self::EuropeanUnion => 300,      // 3x
            Self::UnitedArabEmirates => 500, // 5x (highest due to healthcare sovereignty)
            Self::Singapore => 350,          // 3.5x
            Self::UnitedStates => 250,       // 2.5x
            Self::Switzerland => 600,        // 6x (banking data premium)
            Self::Japan => 280,              // 2.8x
            Self::Australia => 220,          // 2.2x
            Self::UnitedKingdom => 280,      // 2.8x
            Self::China => 400,              // 4x (compliance complexity)
        };

        // Verified data gets additional 50% premium
        if verified {
            (((base as u32) * 150) / 100) as u16
        } else {
            base
        }
    }

    /// Get region code (ISO 3166-1)
    pub fn region_code(&self) -> &'static str {
        match self {
            Self::Public => "INTL",
            Self::EuropeanUnion => "EU",
            Self::UnitedArabEmirates => "AE",
            Self::Singapore => "SG",
            Self::UnitedStates => "US",
            Self::Switzerland => "CH",
            Self::Japan => "JP",
            Self::Australia => "AU",
            Self::UnitedKingdom => "GB",
            Self::China => "CN",
        }
    }

    /// Parse from region string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "INTL" | "PUBLIC" => Some(Self::Public),
            "EU" | "EUR" | "EUROPEAN_UNION" => Some(Self::EuropeanUnion),
            "AE" | "UAE" | "UNITED_ARAB_EMIRATES" => Some(Self::UnitedArabEmirates),
            "SG" | "SINGAPORE" => Some(Self::Singapore),
            "US" | "USA" | "UNITED_STATES" => Some(Self::UnitedStates),
            "CH" | "SWITZERLAND" => Some(Self::Switzerland),
            "JP" | "JAPAN" => Some(Self::Japan),
            "AU" | "AUSTRALIA" => Some(Self::Australia),
            "GB" | "UK" | "UNITED_KINGDOM" => Some(Self::UnitedKingdom),
            "CN" | "CHINA" => Some(Self::China),
            _ => None,
        }
    }
}

// =============================================================================
// DATA VERIFICATION LEVEL
// =============================================================================

/// Data verification level for sovereignty premium
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataVerificationLevel {
    /// Unverified public data
    Unverified = 0,
    /// Self-attested by provider
    SelfAttested = 1,
    /// Third-party verified
    ThirdPartyVerified = 2,
    /// Government/Authority verified
    AuthorityVerified = 3,
    /// TEE-attested verification
    TeeAttested = 4,
    /// ZK-proof verified (highest trust)
    ZkProofVerified = 5,
}

impl DataVerificationLevel {
    /// Get verification premium multiplier (basis points)
    pub fn verification_premium_bps(&self) -> u16 {
        match self {
            Self::Unverified => 100,         // 1x (no premium)
            Self::SelfAttested => 110,       // 1.1x
            Self::ThirdPartyVerified => 150, // 1.5x
            Self::AuthorityVerified => 200,  // 2x
            Self::TeeAttested => 250,        // 2.5x
            Self::ZkProofVerified => 300,    // 3x
        }
    }

    /// Is this level considered "verified" for premium calculation?
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            Self::ThirdPartyVerified
                | Self::AuthorityVerified
                | Self::TeeAttested
                | Self::ZkProofVerified
        )
    }
}

// =============================================================================
// COMPUTE REGISTRY - TRACKS VERIFIED OPERATIONS
// =============================================================================

/// Verified compute operation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeOperationRecord {
    /// Operation ID (hash of job + timestamp)
    pub operation_id: Hash,

    /// Job ID that generated this record
    pub job_id: JobId,

    /// Timestamp of verification
    pub timestamp: u64,

    /// Number of verified FLOPS/operations
    pub verified_ops: u128,

    /// TEE type used (SGX, Nitro, SEV)
    pub tee_type: TeeVerificationType,

    /// Verification proof hash
    pub proof_hash: Hash,

    /// GPU/Accelerator type identifier
    pub hardware_id: String,

    /// Was this a zkML verification?
    pub zk_verified: bool,
}

/// TEE verification type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TeeVerificationType {
    /// Intel SGX
    IntelSgx = 1,
    /// AWS Nitro Enclaves
    AwsNitro = 2,
    /// AMD SEV-SNP
    AmdSev = 3,
    /// ARM TrustZone
    ArmTrustzone = 4,
    /// Software simulation (devnet only)
    Simulated = 255,
}

/// Node compute statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeComputeStats {
    /// Node address
    pub node: Address,

    /// Total verified operations (rolling 30-day window)
    pub verified_ops_30d: u128,

    /// Total verified operations (all time)
    pub verified_ops_total: u128,

    /// Total jobs completed successfully
    pub jobs_completed: u64,

    /// Total jobs failed
    pub jobs_failed: u64,

    /// Success rate (basis points, 10000 = 100%)
    pub success_rate_bps: u16,

    /// Average operations per job
    pub avg_ops_per_job: u128,

    /// Hardware tier (based on proven capability)
    pub hardware_tier: HardwareTier,

    /// Last update timestamp
    pub last_updated: u64,

    /// Recent operation records (for 30-day window calculation)
    pub recent_operations: Vec<ComputeOperationRecord>,
}

impl NodeComputeStats {
    /// Create new stats for a node
    pub fn new(node: Address) -> Self {
        Self {
            node,
            verified_ops_30d: 0,
            verified_ops_total: 0,
            jobs_completed: 0,
            jobs_failed: 0,
            success_rate_bps: 10000, // Start at 100%
            avg_ops_per_job: 0,
            hardware_tier: HardwareTier::Entry,
            last_updated: 0,
            recent_operations: Vec::new(),
        }
    }

    /// Add a verified operation record
    pub fn add_operation(&mut self, record: ComputeOperationRecord, current_time: u64) {
        self.verified_ops_total += record.verified_ops;
        self.jobs_completed += 1;

        // Update rolling window
        self.recent_operations.push(record);
        self.prune_old_operations(current_time);

        // Recalculate 30-day total
        self.verified_ops_30d = self.recent_operations.iter().map(|r| r.verified_ops).sum();

        // Update average
        if self.jobs_completed > 0 {
            self.avg_ops_per_job = self.verified_ops_total / self.jobs_completed as u128;
        }

        // Update success rate
        let total_jobs = self.jobs_completed + self.jobs_failed;
        if total_jobs > 0 {
            self.success_rate_bps =
                ((self.jobs_completed as u128 * 10000) / total_jobs as u128) as u16;
        }

        // Update hardware tier based on performance
        self.update_hardware_tier();

        self.last_updated = current_time;
    }

    /// Record a job failure
    pub fn record_failure(&mut self, current_time: u64) {
        self.jobs_failed += 1;

        let total_jobs = self.jobs_completed + self.jobs_failed;
        if total_jobs > 0 {
            self.success_rate_bps =
                ((self.jobs_completed as u128 * 10000) / total_jobs as u128) as u16;
        }

        self.last_updated = current_time;
    }

    /// Remove operations older than 30 days
    fn prune_old_operations(&mut self, current_time: u64) {
        let cutoff = current_time.saturating_sub(COMPUTE_VERIFICATION_WINDOW);
        self.recent_operations.retain(|r| r.timestamp >= cutoff);
    }

    /// Update hardware tier based on proven compute capability
    fn update_hardware_tier(&mut self) {
        self.hardware_tier = if self.verified_ops_30d >= 1_000_000_000_000 {
            // 1T ops/30d
            HardwareTier::Enterprise
        } else if self.verified_ops_30d >= 100_000_000_000 {
            // 100B ops/30d
            HardwareTier::Professional
        } else if self.verified_ops_30d >= 10_000_000_000 {
            // 10B ops/30d
            HardwareTier::Standard
        } else if self.verified_ops_30d >= 1_000_000_000 {
            // 1B ops/30d
            HardwareTier::Basic
        } else {
            HardwareTier::Entry
        };
    }

    /// Calculate compute multiplier for rewards
    /// Formula: 1.0 + log10(verified_ops) / 10
    /// Range: 1.0x to ~2.5x for extreme compute
    pub fn compute_multiplier_bps(&self) -> u16 {
        if self.verified_ops_30d == 0 {
            return 1000; // 1.0x base
        }

        // log10 calculation using integer math
        // log10(x) ≈ number of digits - 1
        let log_value = self.log10_approx(self.verified_ops_30d);

        // Scale: log10(1M) = 6 → +60% bonus, log10(1T) = 12 → +120% bonus
        // Cap at 150% bonus (2.5x total)
        let bonus_bps = (log_value as u32 * 100).min(1500);

        1000 + bonus_bps as u16 // 1.0x + bonus
    }

    /// Approximate log10 using integer math
    fn log10_approx(&self, value: u128) -> u32 {
        if value == 0 {
            return 0;
        }

        // Count digits (approximate log10)
        let mut digits = 0u32;
        let mut v = value;
        while v > 0 {
            v /= 10;
            digits += 1;
        }
        digits.saturating_sub(1)
    }
}

/// Hardware performance tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum HardwareTier {
    /// Entry level (< 1B ops/30d)
    Entry = 0,
    /// Basic tier (1B-10B ops/30d)
    Basic = 1,
    /// Standard tier (10B-100B ops/30d)
    Standard = 2,
    /// Professional tier (100B-1T ops/30d)
    Professional = 3,
    /// Enterprise tier (> 1T ops/30d)
    Enterprise = 4,
}

impl HardwareTier {
    /// Get tier bonus for rewards (basis points)
    pub fn tier_bonus_bps(&self) -> u16 {
        match self {
            Self::Entry => 0,
            Self::Basic => 50,         // +0.5%
            Self::Standard => 150,     // +1.5%
            Self::Professional => 300, // +3%
            Self::Enterprise => 500,   // +5%
        }
    }
}

// =============================================================================
// COMPLIANCE BOND REGISTRY
// =============================================================================

/// Active compliance bond
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceBond {
    /// Bond ID
    pub bond_id: Hash,

    /// Node address that posted the bond
    pub node: Address,

    /// Bond type
    pub bond_type: ComplianceBondType,

    /// Bond amount (in AETHEL wei)
    pub amount: TokenAmount,

    /// Bond creation timestamp
    pub created_at: u64,

    /// Bond expiry timestamp (0 = no expiry)
    pub expires_at: u64,

    /// Is the bond currently active?
    pub active: bool,

    /// Number of jobs processed under this bond
    pub jobs_processed: u64,

    /// Total value of data processed under this bond
    pub data_value_processed: TokenAmount,

    /// Last job timestamp
    pub last_job_at: u64,
}

impl ComplianceBond {
    /// Create new compliance bond
    pub fn new(
        bond_id: Hash,
        node: Address,
        bond_type: ComplianceBondType,
        amount: TokenAmount,
        created_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            bond_id,
            node,
            bond_type,
            amount,
            created_at,
            expires_at,
            active: true,
            jobs_processed: 0,
            data_value_processed: 0,
            last_job_at: 0,
        }
    }

    /// Check if bond is valid at given time
    pub fn is_valid(&self, current_time: u64) -> bool {
        self.active && (self.expires_at == 0 || current_time < self.expires_at)
    }

    /// Record a job processed under this bond
    pub fn record_job(&mut self, data_value: TokenAmount, timestamp: u64) {
        self.jobs_processed += 1;
        self.data_value_processed += data_value;
        self.last_job_at = timestamp;
    }
}

/// Compliance bond liquidation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondLiquidation {
    /// Liquidation ID
    pub liquidation_id: Hash,

    /// Bond that was liquidated
    pub bond_id: Hash,

    /// Node that was slashed
    pub node: Address,

    /// Victim (data owner) who received payout
    pub victim: Address,

    /// Total bond amount
    pub bond_amount: TokenAmount,

    /// Amount paid to victim (80%)
    pub victim_payout: TokenAmount,

    /// Amount burned (20%)
    pub burned: TokenAmount,

    /// Reason for liquidation
    pub reason: LiquidationReason,

    /// Evidence hash (attestation failure proof)
    pub evidence_hash: Hash,

    /// Timestamp
    pub timestamp: u64,
}

/// Reason for bond liquidation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum LiquidationReason {
    /// TEE attestation failure
    TeeAttestationFailure = 1,
    /// Data breach detected
    DataBreach = 2,
    /// Unauthorized data access
    UnauthorizedAccess = 3,
    /// Compliance audit failure
    AuditFailure = 4,
    /// Privacy violation
    PrivacyViolation = 5,
    /// Key compromise
    KeyCompromise = 6,
}

// =============================================================================
// CONGESTION-SQUARED BURN ENGINE
// =============================================================================

/// Congestion metrics for burn calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CongestionMetrics {
    /// Current block gas used
    pub current_block_gas: u64,

    /// Maximum block gas capacity
    pub max_block_gas: u64,

    /// Current network load (0-10000 basis points)
    pub load_bps: u16,

    /// Rolling average load (smoothed)
    pub avg_load_bps: u16,

    /// Current burn rate (basis points)
    pub current_burn_rate_bps: u16,

    /// Total burned this epoch
    pub epoch_burned: TokenAmount,

    /// Total burned all time
    pub total_burned: TokenAmount,

    /// Block count for averaging
    pub block_count: u64,

    /// Last update timestamp
    pub last_updated: u64,
}

impl Default for CongestionMetrics {
    fn default() -> Self {
        Self {
            current_block_gas: 0,
            max_block_gas: 30_000_000,
            load_bps: 0,
            avg_load_bps: 0,
            current_burn_rate_bps: MIN_BURN_RATE_BPS,
            epoch_burned: 0,
            total_burned: 0,
            block_count: 0,
            last_updated: 0,
        }
    }
}

impl CongestionMetrics {
    /// Update metrics with new block data
    pub fn update_block(&mut self, gas_used: u64, gas_limit: u64, timestamp: u64) {
        self.current_block_gas = gas_used;
        self.max_block_gas = gas_limit;

        // Calculate current load
        self.load_bps = if gas_limit > 0 {
            ((gas_used as u128 * 10000) / gas_limit as u128) as u16
        } else {
            0
        };

        // Exponential moving average (alpha = 0.1)
        // avg = avg * 0.9 + new * 0.1
        self.avg_load_bps =
            ((self.avg_load_bps as u32 * 90 + self.load_bps as u32 * 10) / 100) as u16;

        // Calculate congestion-squared burn rate
        self.current_burn_rate_bps = self.calculate_burn_rate();

        self.block_count += 1;
        self.last_updated = timestamp;
    }

    /// Calculate burn rate using congestion-squared formula
    /// Formula: BurnRate = B_min + (B_max - B_min) × (load/max_load)²
    pub fn calculate_burn_rate(&self) -> u16 {
        let load_ratio = self.avg_load_bps as f64 / 10000.0;

        // Square the load ratio for exponential burn
        let squared_factor = load_ratio * load_ratio;

        // Calculate dynamic burn
        let range = MAX_BURN_RATE_BPS - MIN_BURN_RATE_BPS;
        let dynamic_burn = (range as f64 * squared_factor) as u16;

        MIN_BURN_RATE_BPS + dynamic_burn
    }

    /// Calculate burn amount for a transaction fee
    pub fn calculate_burn(&self, fee: TokenAmount) -> TokenAmount {
        (fee * self.current_burn_rate_bps as u128) / 10000
    }

    /// Record a burn
    pub fn record_burn(&mut self, amount: TokenAmount) {
        self.epoch_burned += amount;
        self.total_burned += amount;
    }

    /// Reset epoch counters
    pub fn reset_epoch(&mut self) {
        self.epoch_burned = 0;
    }
}

// =============================================================================
// SOVEREIGNTY ORACLE - DATA PRICING ENGINE
// =============================================================================

/// Oracle data request with sovereignty pricing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleDataRequest {
    /// Request ID
    pub request_id: Hash,

    /// Requesting address
    pub requester: Address,

    /// Data provider address
    pub provider: Address,

    /// Data region (sovereignty)
    pub region: SovereigntyRegion,

    /// Verification level
    pub verification_level: DataVerificationLevel,

    /// Data category
    pub category: DataCategory,

    /// Base price (before premium)
    pub base_price: TokenAmount,

    /// Calculated premium multiplier
    pub premium_multiplier_bps: u16,

    /// Final price after premium
    pub final_price: TokenAmount,

    /// Request timestamp
    pub timestamp: u64,

    /// Was the request fulfilled?
    pub fulfilled: bool,
}

/// Data category for oracle pricing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum DataCategory {
    /// Public data (weather, market indices)
    Public = 0,
    /// Financial data (stock prices, exchange rates)
    Financial = 1,
    /// Healthcare/Medical data
    Healthcare = 2,
    /// Personal Identity data
    Identity = 3,
    /// Proprietary/Commercial data
    Commercial = 4,
    /// Government/Regulatory data
    Government = 5,
    /// IoT/Sensor data
    IoTSensor = 6,
    /// AI Model weights/parameters
    AiModelData = 7,
}

impl DataCategory {
    /// Get base price multiplier (basis points)
    pub fn base_multiplier_bps(&self) -> u16 {
        match self {
            Self::Public => 100,      // 1x
            Self::Financial => 200,   // 2x
            Self::Healthcare => 400,  // 4x
            Self::Identity => 500,    // 5x
            Self::Commercial => 300,  // 3x
            Self::Government => 350,  // 3.5x
            Self::IoTSensor => 150,   // 1.5x
            Self::AiModelData => 800, // 8x (highest value)
        }
    }
}

/// Sovereignty Oracle engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereigntyOracle {
    /// Base price per data request (in AETHEL wei)
    pub base_price: TokenAmount,

    /// Total requests processed
    pub total_requests: u64,

    /// Total premium collected
    pub total_premium_collected: TokenAmount,

    /// Requests by region
    pub requests_by_region: HashMap<u8, u64>,

    /// Revenue by region
    pub revenue_by_region: HashMap<u8, TokenAmount>,

    /// Provider statistics
    pub provider_stats: HashMap<Address, ProviderStats>,
}

impl Default for SovereigntyOracle {
    fn default() -> Self {
        Self {
            base_price: ONE_AETHEL / 100, // 0.01 AETHEL base
            total_requests: 0,
            total_premium_collected: 0,
            requests_by_region: HashMap::new(),
            revenue_by_region: HashMap::new(),
            provider_stats: HashMap::new(),
        }
    }
}

impl SovereigntyOracle {
    /// Calculate price for data access
    pub fn calculate_price(
        &self,
        region: SovereigntyRegion,
        verification: DataVerificationLevel,
        category: DataCategory,
    ) -> (TokenAmount, u16) {
        // Base price
        let base = self.base_price;

        // Category multiplier
        let category_mult = category.base_multiplier_bps();

        // Sovereignty premium
        let sovereignty_mult = region.premium_multiplier_bps(verification.is_verified());

        // Verification premium
        let verification_mult = verification.verification_premium_bps();

        // Combined multiplier (multiply all factors, divide by 100 for each)
        // multiplier = (category/100) * (sovereignty/100) * (verification/100)
        let combined_mult =
            (category_mult as u128 * sovereignty_mult as u128 * verification_mult as u128) / 10000;

        // Final price
        let final_price = (base * combined_mult) / 100;

        (final_price, combined_mult as u16)
    }

    /// Process a data request
    pub fn process_request(
        &mut self,
        request_id: Hash,
        requester: Address,
        provider: Address,
        region: SovereigntyRegion,
        verification: DataVerificationLevel,
        category: DataCategory,
        timestamp: u64,
    ) -> OracleDataRequest {
        let (final_price, multiplier) = self.calculate_price(region, verification, category);

        // Update statistics
        self.total_requests += 1;
        self.total_premium_collected += final_price;

        *self.requests_by_region.entry(region as u8).or_insert(0) += 1;
        *self.revenue_by_region.entry(region as u8).or_insert(0) += final_price;

        // Update provider stats
        let provider_stats = self
            .provider_stats
            .entry(provider)
            .or_insert_with(|| ProviderStats::new(provider));
        provider_stats.record_request(final_price, region, timestamp);

        OracleDataRequest {
            request_id,
            requester,
            provider,
            region,
            verification_level: verification,
            category,
            base_price: self.base_price,
            premium_multiplier_bps: multiplier,
            final_price,
            timestamp,
            fulfilled: false,
        }
    }
}

/// Data provider statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderStats {
    /// Provider address
    pub provider: Address,

    /// Total requests fulfilled
    pub total_requests: u64,

    /// Total earnings
    pub total_earnings: TokenAmount,

    /// Requests by region
    pub requests_by_region: HashMap<u8, u64>,

    /// Average premium earned (basis points)
    pub avg_premium_bps: u16,

    /// Reputation score (0-10000)
    pub reputation_score: u16,

    /// Last activity timestamp
    pub last_active: u64,
}

impl ProviderStats {
    pub fn new(provider: Address) -> Self {
        Self {
            provider,
            total_requests: 0,
            total_earnings: 0,
            requests_by_region: HashMap::new(),
            avg_premium_bps: 0,
            reputation_score: 5000, // Start at 50%
            last_active: 0,
        }
    }

    pub fn record_request(
        &mut self,
        price: TokenAmount,
        region: SovereigntyRegion,
        timestamp: u64,
    ) {
        self.total_requests += 1;
        self.total_earnings += price;
        *self.requests_by_region.entry(region as u8).or_insert(0) += 1;
        self.last_active = timestamp;
    }
}

// =============================================================================
// PROOF-OF-USEFUL-WORK ENGINE - MAIN COORDINATOR
// =============================================================================

/// Configuration for the PoUW Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUWConfig {
    /// Base APY for staking (basis points)
    pub base_apy_bps: u16,

    /// Maximum compute multiplier
    pub max_compute_multiplier_bps: u16,

    /// Minimum burn rate
    pub min_burn_rate_bps: u16,

    /// Maximum burn rate
    pub max_burn_rate_bps: u16,

    /// Victim payout percentage on bond liquidation
    pub victim_payout_bps: u16,

    /// Burn percentage on bond liquidation
    pub bond_burn_bps: u16,

    /// Compute verification window (seconds)
    pub compute_window_secs: u64,

    /// Minimum compute ops for tier bonuses
    pub min_ops_for_bonus: u128,

    /// Enable compute-weighted rewards
    pub enable_compute_weight: bool,

    /// Enable compliance bonds
    pub enable_compliance_bonds: bool,

    /// Enable congestion-squared burn
    pub enable_congestion_burn: bool,

    /// Enable sovereignty premium
    pub enable_sovereignty_premium: bool,
}

impl Default for PoUWConfig {
    fn default() -> Self {
        Self {
            base_apy_bps: BASE_APY_BPS,
            max_compute_multiplier_bps: MAX_COMPUTE_MULTIPLIER_BPS,
            min_burn_rate_bps: MIN_BURN_RATE_BPS,
            max_burn_rate_bps: MAX_BURN_RATE_BPS,
            victim_payout_bps: COMPLIANCE_VICTIM_PAYOUT_BPS,
            bond_burn_bps: COMPLIANCE_BURN_BPS,
            compute_window_secs: COMPUTE_VERIFICATION_WINDOW,
            min_ops_for_bonus: COMPUTE_TIER_THRESHOLD,
            enable_compute_weight: true,
            enable_compliance_bonds: true,
            enable_congestion_burn: true,
            enable_sovereignty_premium: true,
        }
    }
}

impl PoUWConfig {
    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self::default()
    }

    /// Testnet configuration (relaxed parameters)
    pub fn testnet() -> Self {
        Self {
            min_burn_rate_bps: 300,
            max_burn_rate_bps: 1500,
            min_ops_for_bonus: 100_000, // Lower threshold for testing
            ..Default::default()
        }
    }

    /// DevNet configuration (minimal requirements)
    pub fn devnet() -> Self {
        Self {
            min_burn_rate_bps: 100,
            max_burn_rate_bps: 1000,
            min_ops_for_bonus: 1000,
            enable_compliance_bonds: false, // Disabled for easy testing
            ..Default::default()
        }
    }
}

/// The Proof-of-Useful-Work Tokenomics Engine
///
/// This is the main coordinator that implements all 4 economic moats:
/// 1. Compute-Weighted Multiplier (Anti-Whale)
/// 2. Regulatory Bonding Curves (Compliance-as-an-Asset)
/// 3. Congestion-Squared Deflation (Burning²)
/// 4. Sovereignty Premium (Oracle Pricing)
pub struct PoUWEngine {
    /// Configuration
    config: PoUWConfig,

    /// MOAT 1: Compute registry - tracks verified ops per node
    compute_registry: HashMap<Address, NodeComputeStats>,

    /// MOAT 2: Compliance bonds - tracks active insurance bonds
    compliance_bonds: HashMap<Address, Vec<ComplianceBond>>,

    /// Bond ID to address lookup
    bond_lookup: HashMap<Hash, Address>,

    /// Bond liquidation history
    liquidation_history: Vec<BondLiquidation>,

    /// MOAT 3: Congestion metrics for burn calculation
    congestion: CongestionMetrics,

    /// MOAT 4: Sovereignty oracle for data pricing
    sovereignty_oracle: SovereigntyOracle,

    /// Total staked in the system
    total_staked: TokenAmount,

    /// Node stake amounts (for reward calculation)
    node_stakes: HashMap<Address, TokenAmount>,

    /// Node cooldowns (after attestation failure)
    node_cooldowns: HashMap<Address, u64>,

    /// Events pending emission
    events: Vec<PoUWEvent>,

    /// Current epoch
    current_epoch: u64,

    /// Current timestamp
    current_time: u64,
}

impl PoUWEngine {
    /// Create new PoUW Engine
    pub fn new(config: PoUWConfig) -> Self {
        Self {
            config,
            compute_registry: HashMap::new(),
            compliance_bonds: HashMap::new(),
            bond_lookup: HashMap::new(),
            liquidation_history: Vec::new(),
            congestion: CongestionMetrics::default(),
            sovereignty_oracle: SovereigntyOracle::default(),
            total_staked: 0,
            node_stakes: HashMap::new(),
            node_cooldowns: HashMap::new(),
            events: Vec::new(),
            current_epoch: 0,
            current_time: 0,
        }
    }

    /// Create with default mainnet configuration
    pub fn mainnet() -> Self {
        Self::new(PoUWConfig::mainnet())
    }

    // =========================================================================
    // MOAT 1: COMPUTE-WEIGHTED MULTIPLIER (ANTI-WHALE)
    // =========================================================================

    /// Calculate epoch reward for a node using compute-weighted formula
    ///
    /// Formula: Reward = (Stake × APY) × (1 + log₁₀(ComputeOps) / 10)
    ///
    /// This ensures:
    /// - VC with $10M stake but 0 GPUs → 1.0x multiplier
    /// - Data Center with $1M stake + 500 H100s → up to 2.5x multiplier
    pub fn calculate_epoch_reward(&self, node: &Address, epoch_duration_secs: u64) -> TokenAmount {
        // Get staked amount
        let staked = *self.node_stakes.get(node).unwrap_or(&0);
        if staked == 0 {
            return 0;
        }

        // Base reward: Stake × (APY / seconds_per_year) × epoch_duration
        let seconds_per_year: u64 = 365 * 24 * 60 * 60;
        let base_reward = (staked * self.config.base_apy_bps as u128 * epoch_duration_secs as u128)
            / (10000 * seconds_per_year as u128);

        if !self.config.enable_compute_weight {
            return base_reward;
        }

        // Get compute multiplier
        let compute_stats = self.compute_registry.get(node);
        let multiplier_bps = compute_stats
            .map(|s| s.compute_multiplier_bps())
            .unwrap_or(1000); // 1.0x default

        // Apply hardware tier bonus
        let tier_bonus = compute_stats
            .map(|s| s.hardware_tier.tier_bonus_bps())
            .unwrap_or(0);

        // Total multiplier = base + tier bonus
        let total_multiplier_bps = multiplier_bps + tier_bonus;

        // Cap at maximum multiplier
        let capped_multiplier = total_multiplier_bps.min(self.config.max_compute_multiplier_bps);

        // Apply multiplier
        (base_reward * capped_multiplier as u128) / 1000
    }

    /// Register verified compute operations for a node
    pub fn register_compute_operation(
        &mut self,
        node: Address,
        job_id: JobId,
        verified_ops: u128,
        tee_type: TeeVerificationType,
        proof_hash: Hash,
        hardware_id: String,
        zk_verified: bool,
    ) -> Result<()> {
        // Create operation record
        let operation_id = self.generate_operation_id(&node, &job_id, self.current_time);

        let record = ComputeOperationRecord {
            operation_id,
            job_id,
            timestamp: self.current_time,
            verified_ops,
            tee_type,
            proof_hash,
            hardware_id,
            zk_verified,
        };

        // Get or create node stats
        let stats = self
            .compute_registry
            .entry(node)
            .or_insert_with(|| NodeComputeStats::new(node));

        // Add operation
        let old_multiplier = stats.compute_multiplier_bps();
        stats.add_operation(record, self.current_time);
        let new_multiplier = stats.compute_multiplier_bps();

        // Emit event if multiplier changed significantly
        if new_multiplier != old_multiplier {
            self.events.push(PoUWEvent::ComputeMultiplierUpdated {
                node,
                old_multiplier_bps: old_multiplier,
                new_multiplier_bps: new_multiplier,
                verified_ops_30d: stats.verified_ops_30d,
                hardware_tier: stats.hardware_tier as u8,
            });
        }

        Ok(())
    }

    /// Record a job failure for a node
    pub fn record_compute_failure(&mut self, node: Address) {
        let stats = self
            .compute_registry
            .entry(node)
            .or_insert_with(|| NodeComputeStats::new(node));
        stats.record_failure(self.current_time);
    }

    // =========================================================================
    // MOAT 2: REGULATORY BONDING CURVES (COMPLIANCE-AS-AN-ASSET)
    // =========================================================================

    /// Post a compliance bond to process regulated data
    pub fn post_compliance_bond(
        &mut self,
        node: Address,
        bond_type: ComplianceBondType,
        amount: TokenAmount,
        expires_at: u64,
    ) -> Result<Hash> {
        // Check minimum bond amount
        let required = bond_type.required_bond();
        if amount < required {
            return Err(SystemContractError::InsufficientBond {
                required,
                provided: amount,
            });
        }

        // Check node is not in cooldown
        if let Some(&cooldown_until) = self.node_cooldowns.get(&node) {
            if self.current_time < cooldown_until {
                return Err(SystemContractError::NodeInCooldown {
                    until: cooldown_until,
                });
            }
        }

        // Generate bond ID
        let bond_id = self.generate_bond_id(&node, bond_type, self.current_time);

        // Create bond
        let bond = ComplianceBond::new(
            bond_id,
            node,
            bond_type,
            amount,
            self.current_time,
            expires_at,
        );

        // Store bond
        self.compliance_bonds
            .entry(node)
            .or_insert_with(Vec::new)
            .push(bond);
        self.bond_lookup.insert(bond_id, node);

        // Emit event
        self.events.push(PoUWEvent::ComplianceBondPosted {
            bond_id,
            node,
            bond_type: bond_type as u8,
            amount,
            expires_at,
        });

        Ok(bond_id)
    }

    /// Check if a node has a valid bond for a compliance type
    pub fn has_valid_bond(&self, node: &Address, bond_type: ComplianceBondType) -> bool {
        self.compliance_bonds
            .get(node)
            .map(|bonds| {
                bonds
                    .iter()
                    .any(|b| b.bond_type == bond_type && b.is_valid(self.current_time))
            })
            .unwrap_or(false)
    }

    /// Get the total bond amount for a node
    pub fn total_bond_amount(&self, node: &Address) -> TokenAmount {
        self.compliance_bonds
            .get(node)
            .map(|bonds| {
                bonds
                    .iter()
                    .filter(|b| b.is_valid(self.current_time))
                    .map(|b| b.amount)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Execute compliance bond slash (TEE attestation failure)
    ///
    /// When a node fails TEE attestation (proof of data leak):
    /// 1. 80% of bond → Victim (insurance payout)
    /// 2. 20% of bond → Burned (deflationary penalty)
    /// 3. Node enters cooldown (cannot re-stake bonds for 30 days)
    pub fn execute_compliance_slash(
        &mut self,
        node: Address,
        bond_id: Hash,
        victim: Address,
        reason: LiquidationReason,
        evidence_hash: Hash,
    ) -> Result<BondLiquidation> {
        // Find and remove the bond
        let bonds = self
            .compliance_bonds
            .get_mut(&node)
            .ok_or_else(|| SystemContractError::NoBondFound)?;

        let bond_idx = bonds
            .iter()
            .position(|b| b.bond_id == bond_id)
            .ok_or_else(|| SystemContractError::NoBondFound)?;

        let bond = bonds.remove(bond_idx);
        self.bond_lookup.remove(&bond_id);

        // Calculate payouts
        let victim_payout = (bond.amount * self.config.victim_payout_bps as u128) / 10000;
        let burned = bond.amount - victim_payout;

        // Create liquidation record
        let liquidation_id = self.generate_liquidation_id(&node, &bond_id, self.current_time);
        let liquidation = BondLiquidation {
            liquidation_id,
            bond_id,
            node,
            victim,
            bond_amount: bond.amount,
            victim_payout,
            burned,
            reason,
            evidence_hash,
            timestamp: self.current_time,
        };

        // Store liquidation record
        self.liquidation_history.push(liquidation.clone());

        // Apply cooldown to node
        self.node_cooldowns
            .insert(node, self.current_time + ATTESTATION_FAILURE_COOLDOWN);

        // Record burn
        self.congestion.record_burn(burned);

        // Emit event
        self.events.push(PoUWEvent::ComplianceBondLiquidated {
            liquidation_id,
            bond_id,
            node,
            victim,
            bond_amount: bond.amount,
            victim_payout,
            burned,
            reason: reason as u8,
        });

        Ok(liquidation)
    }

    // =========================================================================
    // MOAT 3: CONGESTION-SQUARED DEFLATION (BURNING²)
    // =========================================================================

    /// Update block metrics and recalculate burn rate
    pub fn update_block(&mut self, gas_used: u64, gas_limit: u64, timestamp: u64) {
        self.current_time = timestamp;

        if !self.config.enable_congestion_burn {
            return;
        }

        let old_rate = self.congestion.current_burn_rate_bps;
        self.congestion.update_block(gas_used, gas_limit, timestamp);
        let new_rate = self.congestion.current_burn_rate_bps;

        // Emit event if burn rate changed significantly (> 100 bps)
        if (new_rate as i32 - old_rate as i32).abs() >= 100 {
            self.events.push(PoUWEvent::BurnRateUpdated {
                old_rate_bps: old_rate,
                new_rate_bps: new_rate,
                network_load_bps: self.congestion.avg_load_bps,
                total_burned: self.congestion.total_burned,
            });
        }
    }

    /// Calculate burn amount for a transaction fee using congestion-squared formula
    pub fn calculate_burn(&self, fee: TokenAmount) -> (TokenAmount, u16) {
        if !self.config.enable_congestion_burn {
            // Return minimum burn if disabled
            let burn = (fee * self.config.min_burn_rate_bps as u128) / 10000;
            return (burn, self.config.min_burn_rate_bps);
        }

        let burn = self.congestion.calculate_burn(fee);
        (burn, self.congestion.current_burn_rate_bps)
    }

    /// Process a transaction fee with congestion-squared burn
    pub fn process_fee(&mut self, fee: TokenAmount) -> FeeDistribution {
        let (burn_amount, burn_rate) = self.calculate_burn(fee);

        // Prover always gets 70%
        let prover_amount = (fee * 70) / 100;

        // Validator gets remainder after burn
        let validator_amount = fee
            .saturating_sub(prover_amount)
            .saturating_sub(burn_amount);

        // Record burn
        self.congestion.record_burn(burn_amount);

        // Emit event
        self.events.push(PoUWEvent::FeeProcessed {
            total_fee: fee,
            prover_amount,
            validator_amount,
            burn_amount,
            burn_rate_bps: burn_rate,
            network_load_bps: self.congestion.avg_load_bps,
        });

        FeeDistribution {
            total_fee: fee,
            prover_amount,
            validator_amount,
            burn_amount,
            burn_rate_bps: burn_rate,
        }
    }

    // =========================================================================
    // MOAT 4: SOVEREIGNTY PREMIUM (ORACLE PRICING)
    // =========================================================================

    /// Price data access based on sovereignty and verification
    pub fn price_oracle_data(
        &self,
        region: &str,
        verification: DataVerificationLevel,
        category: DataCategory,
    ) -> (TokenAmount, u16) {
        if !self.config.enable_sovereignty_premium {
            // Return base price if disabled
            return (self.sovereignty_oracle.base_price, 100);
        }

        let sovereignty_region =
            SovereigntyRegion::from_str(region).unwrap_or(SovereigntyRegion::Public);

        self.sovereignty_oracle
            .calculate_price(sovereignty_region, verification, category)
    }

    /// Process a sovereign data request
    pub fn process_oracle_request(
        &mut self,
        requester: Address,
        provider: Address,
        region: &str,
        verification: DataVerificationLevel,
        category: DataCategory,
    ) -> Result<OracleDataRequest> {
        let sovereignty_region =
            SovereigntyRegion::from_str(region).unwrap_or(SovereigntyRegion::Public);

        // Generate request ID
        let request_id = self.generate_request_id(&requester, &provider, self.current_time);

        // Process request
        let request = self.sovereignty_oracle.process_request(
            request_id,
            requester,
            provider,
            sovereignty_region,
            verification,
            category,
            self.current_time,
        );

        // Emit event
        self.events.push(PoUWEvent::SovereigntyPremiumCharged {
            request_id,
            requester,
            provider,
            region: sovereignty_region as u8,
            verification_level: verification as u8,
            category: category as u8,
            base_price: request.base_price,
            premium_multiplier_bps: request.premium_multiplier_bps,
            final_price: request.final_price,
        });

        Ok(request)
    }

    // =========================================================================
    // STAKING INTEGRATION
    // =========================================================================

    /// Register a stake for a node
    pub fn register_stake(&mut self, node: Address, amount: TokenAmount) {
        let current = *self.node_stakes.get(&node).unwrap_or(&0);
        self.node_stakes.insert(node, current + amount);
        self.total_staked += amount;
    }

    /// Reduce stake for a node
    pub fn reduce_stake(&mut self, node: Address, amount: TokenAmount) -> Result<()> {
        let current = *self.node_stakes.get(&node).unwrap_or(&0);
        if current < amount {
            return Err(SystemContractError::InsufficientStake {
                required: amount,
                actual: current,
            });
        }
        self.node_stakes.insert(node, current - amount);
        self.total_staked = self.total_staked.saturating_sub(amount);
        Ok(())
    }

    // =========================================================================
    // QUERIES
    // =========================================================================

    /// Get compute statistics for a node
    pub fn get_compute_stats(&self, node: &Address) -> Option<&NodeComputeStats> {
        self.compute_registry.get(node)
    }

    /// Get all compliance bonds for a node
    pub fn get_compliance_bonds(&self, node: &Address) -> Option<&Vec<ComplianceBond>> {
        self.compliance_bonds.get(node)
    }

    /// Get current congestion metrics
    pub fn congestion_metrics(&self) -> &CongestionMetrics {
        &self.congestion
    }

    /// Get sovereignty oracle statistics
    pub fn oracle_stats(&self) -> &SovereigntyOracle {
        &self.sovereignty_oracle
    }

    /// Get current burn rate
    pub fn current_burn_rate(&self) -> u16 {
        self.congestion.current_burn_rate_bps
    }

    /// Get total burned
    pub fn total_burned(&self) -> TokenAmount {
        self.congestion.total_burned
    }

    /// Get engine statistics
    pub fn stats(&self) -> PoUWStats {
        let compute_nodes = self.compute_registry.len() as u32;
        let total_compute_ops: u128 = self
            .compute_registry
            .values()
            .map(|s| s.verified_ops_30d)
            .sum();

        let active_bonds: u64 = self
            .compliance_bonds
            .values()
            .flat_map(|bonds| bonds.iter())
            .filter(|b| b.is_valid(self.current_time))
            .count() as u64;

        let total_bond_value: TokenAmount = self
            .compliance_bonds
            .values()
            .flat_map(|bonds| bonds.iter())
            .filter(|b| b.is_valid(self.current_time))
            .map(|b| b.amount)
            .sum();

        PoUWStats {
            compute_nodes,
            total_compute_ops_30d: total_compute_ops,
            active_compliance_bonds: active_bonds,
            total_bond_value,
            total_liquidations: self.liquidation_history.len() as u64,
            current_burn_rate_bps: self.congestion.current_burn_rate_bps,
            network_load_bps: self.congestion.avg_load_bps,
            total_burned: self.congestion.total_burned,
            total_staked: self.total_staked,
            oracle_requests: self.sovereignty_oracle.total_requests,
            oracle_revenue: self.sovereignty_oracle.total_premium_collected,
        }
    }

    // =========================================================================
    // EPOCH & TIME MANAGEMENT
    // =========================================================================

    /// Set current time
    pub fn set_time(&mut self, timestamp: u64) {
        self.current_time = timestamp;
    }

    /// Start new epoch
    pub fn start_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
        self.congestion.reset_epoch();

        self.events.push(PoUWEvent::EpochStarted {
            epoch,
            timestamp: self.current_time,
            burn_rate_bps: self.congestion.current_burn_rate_bps,
        });
    }

    /// End current epoch
    pub fn end_epoch(&mut self) -> Vec<PoUWEvent> {
        self.events.push(PoUWEvent::EpochEnded {
            epoch: self.current_epoch,
            timestamp: self.current_time,
            total_burned: self.congestion.epoch_burned,
            total_rewards_distributed: 0, // Calculated externally
        });

        self.drain_events()
    }

    /// Drain pending events
    pub fn drain_events(&mut self) -> Vec<PoUWEvent> {
        std::mem::take(&mut self.events)
    }

    // =========================================================================
    // INTERNAL HELPERS
    // =========================================================================

    fn generate_operation_id(&self, node: &Address, job_id: &JobId, timestamp: u64) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pouw-op-v1:");
        hasher.update(node);
        hasher.update(job_id);
        hasher.update(&timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn generate_bond_id(
        &self,
        node: &Address,
        bond_type: ComplianceBondType,
        timestamp: u64,
    ) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pouw-bond-v1:");
        hasher.update(node);
        hasher.update(&[bond_type as u8]);
        hasher.update(&timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn generate_liquidation_id(&self, node: &Address, bond_id: &Hash, timestamp: u64) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pouw-liq-v1:");
        hasher.update(node);
        hasher.update(bond_id);
        hasher.update(&timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn generate_request_id(&self, requester: &Address, provider: &Address, timestamp: u64) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"pouw-oracle-v1:");
        hasher.update(requester);
        hasher.update(provider);
        hasher.update(&timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// =============================================================================
// FEE DISTRIBUTION RESULT
// =============================================================================

/// Result of fee distribution with PoUW
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Total fee processed
    pub total_fee: TokenAmount,

    /// Amount to prover (70%)
    pub prover_amount: TokenAmount,

    /// Amount to validator
    pub validator_amount: TokenAmount,

    /// Amount burned (congestion-squared)
    pub burn_amount: TokenAmount,

    /// Effective burn rate (basis points)
    pub burn_rate_bps: u16,
}

// =============================================================================
// ENGINE STATISTICS
// =============================================================================

/// PoUW Engine statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoUWStats {
    /// Number of compute nodes with verified operations
    pub compute_nodes: u32,

    /// Total verified compute operations (30-day window)
    pub total_compute_ops_30d: u128,

    /// Number of active compliance bonds
    pub active_compliance_bonds: u64,

    /// Total value of active bonds
    pub total_bond_value: TokenAmount,

    /// Total bond liquidations
    pub total_liquidations: u64,

    /// Current burn rate (basis points)
    pub current_burn_rate_bps: u16,

    /// Current network load (basis points)
    pub network_load_bps: u16,

    /// Total tokens burned
    pub total_burned: TokenAmount,

    /// Total tokens staked
    pub total_staked: TokenAmount,

    /// Total oracle requests
    pub oracle_requests: u64,

    /// Total oracle revenue (sovereignty premium)
    pub oracle_revenue: TokenAmount,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_weighted_multiplier() {
        let mut engine = PoUWEngine::new(PoUWConfig::default());
        engine.set_time(1000);

        let node = [1u8; 32];
        engine.register_stake(node, 1_000_000 * ONE_AETHEL);

        // No compute ops → 1.0x multiplier
        let reward_no_compute = engine.calculate_epoch_reward(&node, 86400);

        // Register 1 billion ops
        engine
            .register_compute_operation(
                node,
                [2u8; 32],
                1_000_000_000,
                TeeVerificationType::IntelSgx,
                [3u8; 32],
                "H100".to_string(),
                false,
            )
            .unwrap();

        let reward_with_compute = engine.calculate_epoch_reward(&node, 86400);

        // With compute should be higher
        assert!(reward_with_compute > reward_no_compute);

        // Multiplier should be > 1.0x
        let stats = engine.get_compute_stats(&node).unwrap();
        assert!(stats.compute_multiplier_bps() > 1000);
    }

    #[test]
    fn test_compliance_bond_lifecycle() {
        let mut engine = PoUWEngine::new(PoUWConfig::default());
        engine.set_time(1000);

        let node = [1u8; 32];
        let victim = [2u8; 32];

        // Post a GDPR bond
        let bond_id = engine
            .post_compliance_bond(
                node,
                ComplianceBondType::GdprProcessing,
                10_000 * ONE_AETHEL, // More than minimum
                0,                   // No expiry
            )
            .unwrap();

        // Verify bond exists
        assert!(engine.has_valid_bond(&node, ComplianceBondType::GdprProcessing));

        // Liquidate bond
        let liquidation = engine
            .execute_compliance_slash(
                node,
                bond_id,
                victim,
                LiquidationReason::TeeAttestationFailure,
                [3u8; 32],
            )
            .unwrap();

        // 80% to victim
        assert_eq!(liquidation.victim_payout, (10_000 * ONE_AETHEL * 80) / 100);

        // 20% burned
        assert_eq!(liquidation.burned, (10_000 * ONE_AETHEL * 20) / 100);

        // Bond no longer valid
        assert!(!engine.has_valid_bond(&node, ComplianceBondType::GdprProcessing));

        // Node should be in cooldown
        assert!(engine.node_cooldowns.contains_key(&node));
    }

    #[test]
    fn test_congestion_squared_burn() {
        let mut engine = PoUWEngine::new(PoUWConfig::default());

        // Low load (30%) - should be near minimum burn
        engine.update_block(3_000_000, 10_000_000, 1000);
        let (burn_low, rate_low) = engine.calculate_burn(1000 * ONE_AETHEL);
        assert!(rate_low >= MIN_BURN_RATE_BPS);

        // Update multiple blocks at high load to change EMA
        for i in 0..100 {
            engine.update_block(9_000_000, 10_000_000, 1000 + i);
        }

        // High load (90%) - should be much higher burn (squared effect)
        let (burn_high, rate_high) = engine.calculate_burn(1000 * ONE_AETHEL);

        // High congestion should burn more due to squared effect
        assert!(rate_high > rate_low);
        assert!(burn_high > burn_low);
    }

    #[test]
    fn test_sovereignty_premium_pricing() {
        let engine = PoUWEngine::new(PoUWConfig::default());

        // Public data - no premium
        let (price_public, mult_public) = engine.price_oracle_data(
            "PUBLIC",
            DataVerificationLevel::Unverified,
            DataCategory::Public,
        );

        // UAE healthcare data with TEE verification - highest premium
        let (price_uae, mult_uae) = engine.price_oracle_data(
            "UAE",
            DataVerificationLevel::TeeAttested,
            DataCategory::Healthcare,
        );

        // UAE verified should be much higher
        assert!(price_uae > price_public);
        assert!(mult_uae > mult_public);

        // Switzerland financial - also high
        let (price_ch, _) = engine.price_oracle_data(
            "CH",
            DataVerificationLevel::AuthorityVerified,
            DataCategory::Financial,
        );
        assert!(price_ch > price_public);
    }

    #[test]
    fn test_compliance_bond_requirements() {
        // Test minimum bond requirements
        assert_eq!(
            ComplianceBondType::GdprProcessing.required_bond(),
            5_000 * ONE_AETHEL
        );
        assert_eq!(
            ComplianceBondType::HipaaProcessing.required_bond(),
            10_000 * ONE_AETHEL
        );
        assert_eq!(
            ComplianceBondType::PciDss.required_bond(),
            20_000 * ONE_AETHEL
        );
    }

    #[test]
    fn test_engine_stats() {
        let mut engine = PoUWEngine::new(PoUWConfig::default());
        engine.set_time(1000);

        let node = [1u8; 32];
        engine.register_stake(node, 100_000 * ONE_AETHEL);

        // Register some compute
        engine
            .register_compute_operation(
                node,
                [2u8; 32],
                1_000_000_000,
                TeeVerificationType::IntelSgx,
                [3u8; 32],
                "H100".to_string(),
                false,
            )
            .unwrap();

        // Post a bond
        engine
            .post_compliance_bond(
                node,
                ComplianceBondType::GdprProcessing,
                5_000 * ONE_AETHEL,
                0,
            )
            .unwrap();

        let stats = engine.stats();
        assert_eq!(stats.compute_nodes, 1);
        assert_eq!(stats.active_compliance_bonds, 1);
        assert_eq!(stats.total_staked, 100_000 * ONE_AETHEL);
    }
}
