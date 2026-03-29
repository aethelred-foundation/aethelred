//! # AETHEL Tokenomics Module
//!
//! Enterprise-grade token economics implementation for the Aethelred Protocol.
//!
//! ## Token Specification
//!
//! - **Ticker**: AETHEL
//! - **Precision**: 18 Decimals (1 AETHEL = 10^18 wei)
//! - **Total Genesis Supply**: 10,000,000,000 (10 Billion)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────┐
//! │                           AETHEL TOKENOMICS                                      │
//! ├─────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                  │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                     GENESIS ALLOCATION (10B AETHEL)                        │ │
//! │  │                                                                            │ │
//! │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │ │
//! │  │  │  PoUW       │ │    Core     │ │  Ecosystem  │ │ Strategic   │         │ │
//! │  │  │  Rewards    │ │  Contribs   │ │   Grants    │ │   /Seed     │         │ │
//! │  │  │    30%      │ │    20%      │ │    15%      │ │    5.5%     │         │ │
//! │  │  │   3.0B      │ │   2.0B      │ │   1.5B      │ │   550M      │         │ │
//! │  │  ├─────────────┤ ├─────────────┤ ├─────────────┤ ├─────────────┤         │ │
//! │  │  │ 10yr Linear │ │ 6mo Cliff   │ │ 2% TGE      │ │ 12mo Cliff  │         │ │
//! │  │  │ Compute Pay │ │ 42mo Linear │ │ 6mo Cliff   │ │ 24mo Linear │         │ │
//! │  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘         │ │
//! │  │                                                                            │ │
//! │  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐         │ │
//! │  │  │   Public    │ │  Airdrop    │ │ Treasury    │ │  Insurance  │         │ │
//! │  │  │   Sales     │ │   Seals     │ │   & MM      │ │    Fund     │         │ │
//! │  │  │    7.5%     │ │     7%      │ │     6%      │ │     5%      │         │ │
//! │  │  │   750M      │ │   700M      │ │   600M      │ │   500M      │         │ │
//! │  │  ├─────────────┤ ├─────────────┤ ├─────────────┤ ├─────────────┤         │ │
//! │  │  │ 20% TGE     │ │ 25% TGE     │ │ 25% TGE     │ │ 10% TGE     │         │ │
//! │  │  │ 18mo Linear │ │ 12mo Linear │ │ 36mo Linear │ │ 30mo Linear │         │ │
//! │  │  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘         │ │
//! │  │                                                                            │ │
//! │  │  ┌─────────────┐                                                           │ │
//! │  │  │ Contingency │                                                           │ │
//! │  │  │  Reserve    │                                                           │ │
//! │  │  │     4%      │                                                           │ │
//! │  │  │   400M      │                                                           │ │
//! │  │  ├─────────────┤                                                           │ │
//! │  │  │ 12mo Cliff  │                                                           │ │
//! │  │  │ Vest TBD    │                                                           │ │
//! │  │  └─────────────┘                                                           │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                      │                                          │
//! │                                      ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                         ADAPTIVE BURN ENGINE                               │ │
//! │  │                                                                            │ │
//! │  │   BurnRate = B_min + (B_max - B_min) × (BlockUsage / BlockCapacity)²      │ │
//! │  │                                                                            │ │
//! │  │   ┌─────────────────────────────────────────────────────────────────────┐ │ │
//! │  │   │  Usage 10%  │  Usage 50%  │  Usage 90%  │  Usage 100% │            │ │ │
//! │  │   │  Burn: ~5%  │  Burn: ~9%  │  Burn: ~17% │  Burn: 20%  │            │ │ │
//! │  │   └─────────────────────────────────────────────────────────────────────┘ │ │
//! │  │                                                                            │ │
//! │  │   Effect: Heavy usage → Supply deflation → Value appreciation             │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                      │                                          │
//! │                                      ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                         MINING EMISSION SCHEDULE                           │ │
//! │  │                                                                            │ │
//! │  │   Year 0-4:   100M (25% of Mining)                                        │ │
//! │  │   Year 4-8:    50M (12.5% of Mining)   ← First Halving                   │ │
//! │  │   Year 8-12:   25M (6.25% of Mining)   ← Second Halving                  │ │
//! │  │   ...                                                                      │ │
//! │  │   Year 48-50:  ~390K (Final emissions)                                    │ │
//! │  │                                                                            │ │
//! │  │   Total Duration: ~50 years to full distribution                          │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Author
//!
//! Aethelred Team - Economic Module
//!
//! ## License
//!
//! Apache-2.0

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::error::{Result, SystemContractError};
use super::events::TokenomicsEvent;
use super::types::{Address, TokenAmount};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Token precision (18 decimals).
///
/// CROSS-LAYER DENOMINATION NOTE - Audit fix [C-02]:
/// The Rust VM uses 18-decimal wei, while the Go/Cosmos L1 uses 6-decimal uaethel.
/// Bridging between layers requires a 10^12 scaling factor:
///   EVM/Rust wei = uaethel * 10^12
///   uaethel = EVM/Rust wei / 10^12
pub const DECIMALS: u8 = 18;

/// One AETHEL in wei (10^18)
pub const ONE_AETHEL: TokenAmount = 1_000_000_000_000_000_000;

/// Scaling factor from Go uaethel (6 decimals) to Rust wei (18 decimals).
/// Audit fix [C-02].
pub const UAETHEL_TO_WEI_SCALE: TokenAmount = 1_000_000_000_000; // 10^12

/// Total genesis supply (10 billion AETHEL)
pub const TOTAL_GENESIS_SUPPLY: TokenAmount = 10_000_000_000 * ONE_AETHEL;

/// Compute / PoUW Rewards pool (30%)
pub const COMPUTE_POUW_POOL: TokenAmount = 3_000_000_000 * ONE_AETHEL;

/// Core Contributors pool (20%)
pub const CORE_CONTRIBUTORS_POOL: TokenAmount = 2_000_000_000 * ONE_AETHEL;

/// Ecosystem & Grants pool (15%)
pub const ECOSYSTEM_GRANTS_POOL: TokenAmount = 1_500_000_000 * ONE_AETHEL;

/// Strategic / Seed pool (5.5%)
pub const STRATEGIC_SEED_POOL: TokenAmount = 550_000_000 * ONE_AETHEL;

/// Public Sales pool (7.5%)
pub const PUBLIC_SALES_POOL: TokenAmount = 750_000_000 * ONE_AETHEL;

/// Airdrop / Seals pool (7%)
pub const AIRDROP_SEALS_POOL: TokenAmount = 700_000_000 * ONE_AETHEL;

/// Treasury & Market Maker pool (6%)
pub const TREASURY_MM_POOL: TokenAmount = 600_000_000 * ONE_AETHEL;

/// Insurance Fund pool (5%)
pub const INSURANCE_FUND_POOL: TokenAmount = 500_000_000 * ONE_AETHEL;

/// Contingency Reserve pool (4%)
pub const CONTINGENCY_RESERVE_POOL: TokenAmount = 400_000_000 * ONE_AETHEL;

/// Halving interval in seconds (4 years)
pub const HALVING_INTERVAL_SECS: u64 = 4 * 365 * 24 * 60 * 60;

/// Total emission duration (50 years)
pub const TOTAL_EMISSION_DURATION_SECS: u64 = 50 * 365 * 24 * 60 * 60;

/// Minimum burn rate (5%)
pub const MIN_BURN_RATE_BPS: u16 = 500;

/// Maximum burn rate (20%)
pub const MAX_BURN_RATE_BPS: u16 = 2000;

/// Seconds per year
pub const SECONDS_PER_YEAR: u64 = 365 * 24 * 60 * 60;

// =============================================================================
// ALLOCATION CATEGORIES
// =============================================================================

/// Token allocation category (10B total supply, 9 categories)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AllocationCategory {
    /// PoUW Rewards (30%) - Validator incentives, 10yr linear, no cliff
    ComputePoUW,

    /// Core Contributors (20%) - 6mo cliff, 42mo linear, no TGE
    CoreContributors,

    /// Ecosystem & Grants (15%) - 2% TGE, 6mo cliff, 48mo linear
    EcosystemGrants,

    /// Strategic / Seed (5.5%) - 12mo cliff, 24mo linear, no TGE
    StrategicSeed,

    /// Public Sales (7.5%) - 20% TGE, no cliff, 18mo linear
    PublicSales,

    /// Airdrop / Seals (7%) - 25% TGE, no cliff, 12mo linear
    AirdropSeals,

    /// Treasury & MM (6%) - 25% TGE, no cliff, 36mo linear
    TreasuryMM,

    /// Insurance Fund (5%) - 10% TGE, no cliff, 30mo linear
    InsuranceFund,

    /// Contingency Reserve (4%) - 12mo cliff, vesting TBD
    ContingencyReserve,
}

impl AllocationCategory {
    /// Get the total allocation for this category
    pub fn total_allocation(&self) -> TokenAmount {
        match self {
            Self::ComputePoUW => COMPUTE_POUW_POOL,
            Self::CoreContributors => CORE_CONTRIBUTORS_POOL,
            Self::EcosystemGrants => ECOSYSTEM_GRANTS_POOL,
            Self::StrategicSeed => STRATEGIC_SEED_POOL,
            Self::PublicSales => PUBLIC_SALES_POOL,
            Self::AirdropSeals => AIRDROP_SEALS_POOL,
            Self::TreasuryMM => TREASURY_MM_POOL,
            Self::InsuranceFund => INSURANCE_FUND_POOL,
            Self::ContingencyReserve => CONTINGENCY_RESERVE_POOL,
        }
    }

    /// Get the percentage allocation (basis points)
    pub fn percentage_bps(&self) -> u16 {
        match self {
            Self::ComputePoUW => 3000,       // 30%
            Self::CoreContributors => 2000,  // 20%
            Self::EcosystemGrants => 1500,   // 15%
            Self::StrategicSeed => 550,      // 5.5%
            Self::PublicSales => 750,        // 7.5%
            Self::AirdropSeals => 700,       // 7%
            Self::TreasuryMM => 600,         // 6%
            Self::InsuranceFund => 500,      // 5%
            Self::ContingencyReserve => 400, // 4%
        }
    }

    /// Get the vesting schedule for this category
    pub fn vesting_schedule(&self) -> VestingSchedule {
        match self {
            Self::ComputePoUW => VestingSchedule::Linear {
                cliff: Duration::from_secs(0),                        // No cliff
                duration: Duration::from_secs(10 * SECONDS_PER_YEAR), // 10yr linear (120mo)
                tge_percent: 0,                                       // No TGE unlock
            },
            Self::CoreContributors => VestingSchedule::Linear {
                cliff: Duration::from_secs(SECONDS_PER_YEAR / 2), // 6mo cliff
                duration: Duration::from_secs(4 * SECONDS_PER_YEAR), // 48mo total (6mo cliff + 42mo linear)
                tge_percent: 0,                                      // No TGE unlock
            },
            Self::EcosystemGrants => VestingSchedule::Linear {
                cliff: Duration::from_secs(SECONDS_PER_YEAR / 2), // 6mo cliff
                duration: Duration::from_secs(9 * SECONDS_PER_YEAR / 2), // 54mo total (6mo cliff + 48mo linear)
                tge_percent: 2,                                          // 2% at TGE (30M)
            },
            Self::StrategicSeed => VestingSchedule::Linear {
                cliff: Duration::from_secs(SECONDS_PER_YEAR), // 12mo cliff
                duration: Duration::from_secs(3 * SECONDS_PER_YEAR), // 36mo total (12mo cliff + 24mo linear)
                tge_percent: 0,                                      // No TGE unlock
            },
            Self::PublicSales => VestingSchedule::Linear {
                cliff: Duration::from_secs(0),                           // No cliff
                duration: Duration::from_secs(3 * SECONDS_PER_YEAR / 2), // 18mo linear
                tge_percent: 20,                                         // 20% at TGE (150M)
            },
            Self::AirdropSeals => VestingSchedule::Linear {
                cliff: Duration::from_secs(0),                   // No cliff
                duration: Duration::from_secs(SECONDS_PER_YEAR), // 12mo linear
                tge_percent: 25,                                 // 25% at TGE (175M)
            },
            Self::TreasuryMM => VestingSchedule::Linear {
                cliff: Duration::from_secs(0),                       // No cliff
                duration: Duration::from_secs(3 * SECONDS_PER_YEAR), // 36mo linear
                tge_percent: 25,                                     // 25% at TGE (150M)
            },
            Self::InsuranceFund => VestingSchedule::Linear {
                cliff: Duration::from_secs(0),                           // No cliff
                duration: Duration::from_secs(5 * SECONDS_PER_YEAR / 2), // 30mo linear
                tge_percent: 10,                                         // 10% at TGE (50M)
            },
            Self::ContingencyReserve => VestingSchedule::Linear {
                cliff: Duration::from_secs(SECONDS_PER_YEAR), // 12mo cliff
                duration: Duration::from_secs(5 * SECONDS_PER_YEAR), // Placeholder: 60mo (vesting TBD per governance)
                tge_percent: 0,                                      // No TGE unlock
            },
        }
    }
}

// =============================================================================
// VESTING SCHEDULES
// =============================================================================

/// Vesting schedule type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VestingSchedule {
    /// Immediate unlock (100% at TGE)
    Immediate,

    /// Linear vesting with optional cliff
    Linear {
        /// Cliff duration before any tokens vest
        cliff: Duration,
        /// Total vesting duration (including cliff)
        duration: Duration,
        /// Percentage unlocked at TGE (before cliff)
        tge_percent: u8,
    },

    /// Emission schedule with halvings (for mining rewards)
    Emission {
        /// Interval between halvings
        halving_interval: Duration,
        /// Total emission duration
        total_duration: Duration,
    },

    /// Controlled by DAO governance
    DaoControlled,

    /// Strategic reserve (unlocked by foundation)
    Strategic,
}

impl VestingSchedule {
    /// Calculate vested amount at a given timestamp.
    ///
    /// # Overflow Safety - Audit fix [M-08]
    ///
    /// All intermediate arithmetic uses `u128`. The worst-case multiplication is:
    ///   `total_amount * elapsed_secs`
    /// where `total_amount` ≤ 10B * 10^18 = 10^28 and `elapsed_secs` ≤ 50yr ≈ 1.58*10^9.
    /// Product: ~1.58 * 10^37, well within u128 max (~3.4 * 10^38).
    ///
    /// If AETHEL precision or supply ever increases, revisit with `u256` (via
    /// `ethnum` or `primitive_types`).
    pub fn vested_amount(
        &self,
        total_amount: TokenAmount,
        start_time: u64,
        current_time: u64,
    ) -> TokenAmount {
        if current_time <= start_time {
            return match self {
                Self::Immediate => total_amount,
                Self::Linear { tge_percent, .. } => (total_amount * *tge_percent as u128) / 100,
                _ => 0,
            };
        }

        let elapsed = current_time - start_time;

        match self {
            Self::Immediate => total_amount,

            Self::Linear {
                cliff,
                duration,
                tge_percent,
            } => {
                let tge_amount = (total_amount * *tge_percent as u128) / 100;
                let vesting_amount = total_amount - tge_amount;

                if elapsed < cliff.as_secs() {
                    // Still in cliff period
                    tge_amount
                } else if elapsed >= duration.as_secs() {
                    // Fully vested
                    total_amount
                } else {
                    // Linear vesting after cliff
                    let vesting_elapsed = elapsed - cliff.as_secs();
                    let vesting_duration = duration.as_secs() - cliff.as_secs();
                    let vested =
                        (vesting_amount * vesting_elapsed as u128) / vesting_duration as u128;
                    tge_amount + vested
                }
            }

            Self::Emission {
                halving_interval,
                total_duration,
            } => {
                // Calculate total emissions up to current time
                self.calculate_emission_vested(
                    total_amount,
                    elapsed,
                    halving_interval.as_secs(),
                    total_duration.as_secs(),
                )
            }

            Self::DaoControlled | Self::Strategic => {
                // These are manually controlled
                0
            }
        }
    }

    /// Calculate emissions with halving schedule
    fn calculate_emission_vested(
        &self,
        total_pool: TokenAmount,
        elapsed_secs: u64,
        halving_interval: u64,
        total_duration: u64,
    ) -> TokenAmount {
        if elapsed_secs >= total_duration {
            return total_pool;
        }

        // Calculate how many full halving periods have passed
        let full_periods = elapsed_secs / halving_interval;
        let remaining_in_period = elapsed_secs % halving_interval;

        // Initial emission rate (first 4 years = 25% of total mining pool)
        let initial_period_emission = total_pool / 4; // 25% per period initially

        let mut total_emitted: TokenAmount = 0;
        let mut current_emission = initial_period_emission;

        // Sum up full periods
        for period in 0..full_periods {
            if period > 0 {
                current_emission /= 2; // Halving
            }
            total_emitted += current_emission;
        }

        // Add partial period
        if remaining_in_period > 0 && full_periods < 13 {
            // ~50 years / 4 years = ~12-13 periods
            let period_emission = if full_periods == 0 {
                initial_period_emission
            } else {
                initial_period_emission / (1 << full_periods)
            };
            let partial =
                (period_emission * remaining_in_period as u128) / halving_interval as u128;
            total_emitted += partial;
        }

        total_emitted.min(total_pool)
    }
}

// =============================================================================
// VESTING POSITION
// =============================================================================

/// Individual vesting position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VestingPosition {
    /// Unique position ID
    pub id: u64,

    /// Beneficiary address
    pub beneficiary: Address,

    /// Total amount in this position
    pub total_amount: TokenAmount,

    /// Amount already claimed
    pub claimed_amount: TokenAmount,

    /// Allocation category
    pub category: AllocationCategory,

    /// Custom vesting schedule (if different from category default)
    pub custom_schedule: Option<VestingSchedule>,

    /// Position start time (TGE or grant date)
    pub start_time: u64,

    /// Whether position is revocable
    pub revocable: bool,

    /// Whether position has been revoked
    pub revoked: bool,

    /// Revocation time (if revoked)
    pub revoked_at: Option<u64>,
}

impl VestingPosition {
    /// Calculate currently vested amount
    pub fn vested_amount(&self, current_time: u64) -> TokenAmount {
        if self.revoked {
            // If revoked, vesting stopped at revocation time
            let effective_time = self.revoked_at.unwrap_or(current_time);
            let schedule = self
                .custom_schedule
                .clone()
                .unwrap_or_else(|| self.category.vesting_schedule());
            return schedule.vested_amount(self.total_amount, self.start_time, effective_time);
        }

        let schedule = self
            .custom_schedule
            .clone()
            .unwrap_or_else(|| self.category.vesting_schedule());
        schedule.vested_amount(self.total_amount, self.start_time, current_time)
    }

    /// Calculate claimable amount
    pub fn claimable_amount(&self, current_time: u64) -> TokenAmount {
        let vested = self.vested_amount(current_time);
        vested.saturating_sub(self.claimed_amount)
    }

    /// Claim vested tokens
    pub fn claim(&mut self, current_time: u64) -> TokenAmount {
        let claimable = self.claimable_amount(current_time);
        self.claimed_amount += claimable;
        claimable
    }
}

// =============================================================================
// ADAPTIVE BURN ENGINE
// =============================================================================

/// Configuration for the adaptive burn engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnConfig {
    /// Minimum burn rate (basis points)
    pub min_burn_rate_bps: u16,

    /// Maximum burn rate (basis points)
    pub max_burn_rate_bps: u16,

    /// Exponent for the burn curve (2 = quadratic)
    pub curve_exponent: u8,

    /// Smoothing factor for rate changes (0-100)
    pub smoothing_factor: u8,
}

impl Default for BurnConfig {
    fn default() -> Self {
        Self {
            min_burn_rate_bps: MIN_BURN_RATE_BPS,
            max_burn_rate_bps: MAX_BURN_RATE_BPS,
            curve_exponent: 2,    // Quadratic curve
            smoothing_factor: 50, // 50% smoothing
        }
    }
}

/// Adaptive burn engine implementing congestion-based deflation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveBurnEngine {
    /// Configuration
    config: BurnConfig,

    /// Current effective burn rate (basis points)
    current_rate_bps: u16,

    /// Total tokens burned
    total_burned: TokenAmount,

    /// Tokens burned this epoch
    epoch_burned: TokenAmount,

    /// Running average of block utilization (basis points)
    avg_utilization_bps: u16,

    /// Block count for averaging
    block_count: u64,
}

impl AdaptiveBurnEngine {
    /// Create new burn engine with configuration
    pub fn new(config: BurnConfig) -> Self {
        Self {
            current_rate_bps: config.min_burn_rate_bps,
            config,
            total_burned: 0,
            epoch_burned: 0,
            avg_utilization_bps: 0,
            block_count: 0,
        }
    }

    /// Calculate burn amount for a transaction fee
    ///
    /// Formula: BurnRate = B_min + (B_max - B_min) × (BlockUsage / BlockCapacity)^2
    pub fn calculate_burn(&self, fee_amount: TokenAmount, block_fullness_bps: u16) -> TokenAmount {
        let burn_rate = self.calculate_burn_rate(block_fullness_bps);
        (fee_amount * burn_rate as u128) / 10000
    }

    /// Calculate burn rate based on block fullness using integer-only arithmetic.
    ///
    /// Formula: rate = min + (max - min) * (fullness / 10000)^exponent
    /// Implemented with scaled integer math to avoid f64 precision issues.
    pub fn calculate_burn_rate(&self, block_fullness_bps: u16) -> u16 {
        let range = (self.config.max_burn_rate_bps - self.config.min_burn_rate_bps) as u64;
        let fullness = block_fullness_bps as u64;
        let scale = 10_000u64;

        // Compute fullness^exponent / scale^exponent using integer math.
        // For exponent=2 (default quadratic): (fullness^2) / (10000^2)
        // We use u64 which can hold up to 10000^3 safely (10^12 < 2^64).
        let mut numerator: u64 = 1;
        let mut denominator: u64 = 1;
        for _ in 0..self.config.curve_exponent {
            numerator = numerator.saturating_mul(fullness);
            denominator = denominator.saturating_mul(scale);
        }

        // additional = range * numerator / denominator
        // Use u128 intermediate to avoid overflow for large range * numerator
        let additional = ((range as u128 * numerator as u128) / denominator as u128) as u16;

        self.config.min_burn_rate_bps + additional
    }

    /// Update engine with new block data
    pub fn update_block(&mut self, gas_used: u64, gas_limit: u64) {
        let fullness_bps = if gas_limit > 0 {
            ((gas_used as u128 * 10000) / gas_limit as u128) as u16
        } else {
            0
        };

        // Update running average with smoothing
        let smoothing = self.config.smoothing_factor as u32;
        self.avg_utilization_bps = ((self.avg_utilization_bps as u32 * (100 - smoothing)
            + fullness_bps as u32 * smoothing)
            / 100) as u16;

        // Update current rate based on smoothed utilization
        self.current_rate_bps = self.calculate_burn_rate(self.avg_utilization_bps);

        self.block_count += 1;
    }

    /// Record a burn
    pub fn record_burn(&mut self, amount: TokenAmount) {
        self.total_burned += amount;
        self.epoch_burned += amount;
    }

    /// Reset epoch counters
    pub fn reset_epoch(&mut self) {
        self.epoch_burned = 0;
    }

    /// Get current burn rate
    pub fn current_rate_bps(&self) -> u16 {
        self.current_rate_bps
    }

    /// Get total burned
    pub fn total_burned(&self) -> TokenAmount {
        self.total_burned
    }

    /// Get epoch burned
    pub fn epoch_burned(&self) -> TokenAmount {
        self.epoch_burned
    }

    /// Get average utilization
    pub fn avg_utilization_bps(&self) -> u16 {
        self.avg_utilization_bps
    }
}

// =============================================================================
// MINING EMISSION CALCULATOR
// =============================================================================

/// Mining emission calculator with halving schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionCalculator {
    /// Total mining pool
    total_pool: TokenAmount,

    /// Halving interval in seconds
    halving_interval_secs: u64,

    /// Total emission duration
    total_duration_secs: u64,

    /// Genesis timestamp (TGE)
    genesis_time: u64,

    /// Total emitted so far
    total_emitted: TokenAmount,

    /// Last emission calculation timestamp
    last_calculation_time: u64,
}

impl EmissionCalculator {
    /// Create new emission calculator
    pub fn new(
        total_pool: TokenAmount,
        halving_interval_secs: u64,
        total_duration_secs: u64,
        genesis_time: u64,
    ) -> Self {
        Self {
            total_pool,
            halving_interval_secs,
            total_duration_secs,
            genesis_time,
            total_emitted: 0,
            last_calculation_time: genesis_time,
        }
    }

    /// Create with default parameters
    pub fn default_with_genesis(genesis_time: u64) -> Self {
        Self::new(
            COMPUTE_POUW_POOL,
            HALVING_INTERVAL_SECS,
            TOTAL_EMISSION_DURATION_SECS,
            genesis_time,
        )
    }

    /// Get current emission rate per second
    pub fn current_rate_per_second(&self, current_time: u64) -> TokenAmount {
        if current_time < self.genesis_time {
            return 0;
        }

        let elapsed = current_time - self.genesis_time;
        if elapsed >= self.total_duration_secs {
            return 0;
        }

        // Initial rate: 25% of pool over first halving period
        let initial_rate_per_sec = (self.total_pool / 4) / self.halving_interval_secs as u128;

        // Number of halvings
        let halvings = elapsed / self.halving_interval_secs;
        if halvings >= 13 {
            return 0; // Emissions essentially complete
        }

        // Apply halvings
        initial_rate_per_sec >> halvings
    }

    /// Get emission for a specific block
    pub fn block_emission(&self, block_time: u64, block_duration_secs: u64) -> TokenAmount {
        let rate = self.current_rate_per_second(block_time);
        rate * block_duration_secs as u128
    }

    /// Calculate total emissions up to a time
    pub fn total_emissions_at(&self, current_time: u64) -> TokenAmount {
        if current_time <= self.genesis_time {
            return 0;
        }

        let schedule = VestingSchedule::Emission {
            halving_interval: Duration::from_secs(self.halving_interval_secs),
            total_duration: Duration::from_secs(self.total_duration_secs),
        };

        schedule.vested_amount(self.total_pool, self.genesis_time, current_time)
    }

    /// Update emission state
    pub fn update(&mut self, current_time: u64) -> TokenAmount {
        let new_total = self.total_emissions_at(current_time);
        let new_emissions = new_total.saturating_sub(self.total_emitted);
        self.total_emitted = new_total;
        self.last_calculation_time = current_time;
        new_emissions
    }

    /// Get remaining emissions
    pub fn remaining_emissions(&self) -> TokenAmount {
        self.total_pool.saturating_sub(self.total_emitted)
    }

    /// Get emission schedule info
    pub fn schedule_info(&self, current_time: u64) -> EmissionScheduleInfo {
        let elapsed = current_time.saturating_sub(self.genesis_time);
        let current_period = elapsed / self.halving_interval_secs;
        let next_halving = self.genesis_time + (current_period + 1) * self.halving_interval_secs;

        EmissionScheduleInfo {
            total_pool: self.total_pool,
            total_emitted: self.total_emitted,
            remaining: self.remaining_emissions(),
            current_rate_per_second: self.current_rate_per_second(current_time),
            current_period: current_period as u32,
            next_halving_time: next_halving,
            time_to_next_halving: next_halving.saturating_sub(current_time),
            percent_complete_bps: ((self.total_emitted * 10000) / self.total_pool) as u16,
        }
    }
}

/// Emission schedule information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionScheduleInfo {
    pub total_pool: TokenAmount,
    pub total_emitted: TokenAmount,
    pub remaining: TokenAmount,
    pub current_rate_per_second: TokenAmount,
    pub current_period: u32,
    pub next_halving_time: u64,
    pub time_to_next_halving: u64,
    pub percent_complete_bps: u16,
}

// =============================================================================
// TOKENOMICS MANAGER
// =============================================================================

/// Configuration for the tokenomics manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenomicsConfig {
    /// Genesis timestamp (TGE)
    pub genesis_time: u64,

    /// Burn engine configuration
    pub burn_config: BurnConfig,

    /// Enable adaptive burn
    pub adaptive_burn_enabled: bool,

    /// Minimum transaction fee
    pub min_tx_fee: TokenAmount,

    /// Fee split: prover percentage (basis points)
    pub prover_fee_bps: u16,

    /// Fee split: validator percentage (basis points)
    pub validator_fee_bps: u16,

    /// Fee split: burn percentage (basis points, remainder)
    /// Note: prover + validator + burn should = 10000
    pub burn_fee_bps: u16,
}

impl Default for TokenomicsConfig {
    fn default() -> Self {
        Self {
            genesis_time: 0,
            burn_config: BurnConfig::default(),
            adaptive_burn_enabled: true,
            min_tx_fee: 1_000_000_000_000, // 0.001 AETHEL
            prover_fee_bps: 7000,          // 70%
            validator_fee_bps: 2000,       // 20% (15-25% range)
            burn_fee_bps: 1000,            // 10% (5-15% range)
        }
    }
}

impl TokenomicsConfig {
    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            genesis_time: 0, // Set at launch
            burn_config: BurnConfig::default(),
            adaptive_burn_enabled: true,
            min_tx_fee: 1_000_000_000_000,
            prover_fee_bps: 7000,
            validator_fee_bps: 2000,
            burn_fee_bps: 1000,
        }
    }

    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            genesis_time: 0,
            burn_config: BurnConfig {
                min_burn_rate_bps: 200,
                max_burn_rate_bps: 1000,
                ..Default::default()
            },
            adaptive_burn_enabled: true,
            min_tx_fee: 100_000_000_000,
            prover_fee_bps: 7000,
            validator_fee_bps: 2000,
            burn_fee_bps: 1000,
        }
    }

    /// DevNet configuration
    pub fn devnet() -> Self {
        Self {
            genesis_time: 0,
            burn_config: BurnConfig::default(),
            adaptive_burn_enabled: false, // Disabled for testing
            min_tx_fee: 0,                // Free transactions
            prover_fee_bps: 7000,
            validator_fee_bps: 2500,
            burn_fee_bps: 500,
        }
    }
}

/// The tokenomics manager - coordinates all token economics
pub struct TokenomicsManager {
    /// Configuration
    config: TokenomicsConfig,

    /// Adaptive burn engine
    burn_engine: AdaptiveBurnEngine,

    /// Mining emission calculator
    emission_calculator: EmissionCalculator,

    /// Vesting positions by ID
    vesting_positions: HashMap<u64, VestingPosition>,

    /// Next vesting position ID
    next_position_id: u64,

    /// Total circulating supply
    circulating_supply: TokenAmount,

    /// Total locked in vesting
    total_vesting_locked: TokenAmount,

    /// Category statistics
    category_stats: HashMap<AllocationCategory, CategoryStats>,

    /// Events
    events: Vec<TokenomicsEvent>,
}

/// Statistics for an allocation category
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryStats {
    pub total_allocated: TokenAmount,
    pub total_vested: TokenAmount,
    pub total_claimed: TokenAmount,
    pub position_count: u64,
}

impl TokenomicsManager {
    /// Create new tokenomics manager
    pub fn new(config: TokenomicsConfig) -> Self {
        let burn_engine = AdaptiveBurnEngine::new(config.burn_config.clone());
        let emission_calculator = EmissionCalculator::default_with_genesis(config.genesis_time);

        Self {
            config,
            burn_engine,
            emission_calculator,
            vesting_positions: HashMap::new(),
            next_position_id: 1,
            circulating_supply: 0,
            total_vesting_locked: 0,
            category_stats: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Initialize genesis allocations
    pub fn initialize_genesis(&mut self, allocations: Vec<GenesisAllocation>) -> Result<()> {
        for alloc in allocations {
            self.create_vesting_position(
                alloc.beneficiary,
                alloc.amount,
                alloc.category,
                alloc.custom_schedule,
                self.config.genesis_time,
                alloc.revocable,
            )?;
        }

        // Add public sales TGE unlock to circulating supply immediately
        self.circulating_supply += PUBLIC_SALES_POOL;

        self.events.push(TokenomicsEvent::GenesisInitialized {
            total_supply: TOTAL_GENESIS_SUPPLY,
            circulating: self.circulating_supply,
            locked: self.total_vesting_locked,
        });

        Ok(())
    }

    /// Create a new vesting position
    pub fn create_vesting_position(
        &mut self,
        beneficiary: Address,
        amount: TokenAmount,
        category: AllocationCategory,
        custom_schedule: Option<VestingSchedule>,
        start_time: u64,
        revocable: bool,
    ) -> Result<u64> {
        let position_id = self.next_position_id;
        self.next_position_id += 1;

        let position = VestingPosition {
            id: position_id,
            beneficiary,
            total_amount: amount,
            claimed_amount: 0,
            category,
            custom_schedule,
            start_time,
            revocable,
            revoked: false,
            revoked_at: None,
        };

        self.vesting_positions.insert(position_id, position);
        self.total_vesting_locked += amount;

        // Update category stats
        let stats = self.category_stats.entry(category).or_default();
        stats.total_allocated += amount;
        stats.position_count += 1;

        self.events.push(TokenomicsEvent::VestingPositionCreated {
            position_id,
            beneficiary,
            amount,
            category,
        });

        Ok(position_id)
    }

    /// Claim vested tokens from a position
    pub fn claim_vested(
        &mut self,
        position_id: u64,
        claimer: &Address,
        current_time: u64,
    ) -> Result<TokenAmount> {
        let position = self
            .vesting_positions
            .get_mut(&position_id)
            .ok_or_else(|| SystemContractError::Tokenomics("Position not found".into()))?;

        // Verify claimer is beneficiary
        if &position.beneficiary != claimer {
            return Err(SystemContractError::Tokenomics(
                "Not position beneficiary".into(),
            ));
        }

        let claimable = position.claim(current_time);

        if claimable > 0 {
            self.total_vesting_locked -= claimable;
            self.circulating_supply += claimable;

            // Update category stats
            if let Some(stats) = self.category_stats.get_mut(&position.category) {
                stats.total_claimed += claimable;
            }

            self.events.push(TokenomicsEvent::VestingClaimed {
                position_id,
                beneficiary: position.beneficiary,
                amount: claimable,
            });
        }

        Ok(claimable)
    }

    /// Revoke a vesting position (if revocable)
    pub fn revoke_position(&mut self, position_id: u64, current_time: u64) -> Result<TokenAmount> {
        let position = self
            .vesting_positions
            .get_mut(&position_id)
            .ok_or_else(|| SystemContractError::Tokenomics("Position not found".into()))?;

        if !position.revocable {
            return Err(SystemContractError::Tokenomics(
                "Position is not revocable".into(),
            ));
        }

        if position.revoked {
            return Err(SystemContractError::Tokenomics(
                "Position already revoked".into(),
            ));
        }

        // Calculate unvested amount to return
        let vested = position.vested_amount(current_time);
        let unvested = position.total_amount.saturating_sub(vested);

        position.revoked = true;
        position.revoked_at = Some(current_time);

        self.total_vesting_locked -= unvested;

        self.events.push(TokenomicsEvent::VestingRevoked {
            position_id,
            unvested_returned: unvested,
        });

        Ok(unvested)
    }

    /// Process transaction fee distribution
    pub fn process_fee(
        &mut self,
        fee_amount: TokenAmount,
        block_fullness_bps: u16,
    ) -> FeeDistribution {
        // Calculate burn amount
        let burn_amount = if self.config.adaptive_burn_enabled {
            self.burn_engine
                .calculate_burn(fee_amount, block_fullness_bps)
        } else {
            (fee_amount * self.config.burn_fee_bps as u128) / 10000
        };

        // Record burn
        self.burn_engine.record_burn(burn_amount);

        // Calculate remaining fee split
        let remaining = fee_amount - burn_amount;
        let prover_amount = (remaining * self.config.prover_fee_bps as u128) / 10000;
        let validator_amount = remaining - prover_amount;

        FeeDistribution {
            total_fee: fee_amount,
            prover_amount,
            validator_amount,
            burn_amount,
            effective_burn_rate_bps: ((burn_amount * 10000) / fee_amount) as u16,
        }
    }

    /// Update block metrics
    pub fn update_block(&mut self, gas_used: u64, gas_limit: u64) {
        self.burn_engine.update_block(gas_used, gas_limit);
    }

    /// Get mining emission for block
    pub fn get_block_emission(&self, block_time: u64, block_duration_secs: u64) -> TokenAmount {
        self.emission_calculator
            .block_emission(block_time, block_duration_secs)
    }

    /// Update emission state
    pub fn update_emissions(&mut self, current_time: u64) -> TokenAmount {
        let new_emissions = self.emission_calculator.update(current_time);
        if new_emissions > 0 {
            self.events.push(TokenomicsEvent::MiningEmission {
                amount: new_emissions,
                total_emitted: self.emission_calculator.total_emitted,
            });
        }
        new_emissions
    }

    /// Get supply information
    pub fn supply_info(&self, current_time: u64) -> SupplyInfo {
        let total_vested: TokenAmount = self
            .vesting_positions
            .values()
            .map(|p| p.vested_amount(current_time))
            .sum();

        SupplyInfo {
            total_supply: TOTAL_GENESIS_SUPPLY,
            circulating_supply: self.circulating_supply,
            total_burned: self.burn_engine.total_burned(),
            total_locked: self.total_vesting_locked,
            total_vested,
            mining_emitted: self.emission_calculator.total_emitted,
            mining_remaining: self.emission_calculator.remaining_emissions(),
        }
    }

    /// Get burn statistics
    pub fn burn_stats(&self) -> BurnStats {
        BurnStats {
            total_burned: self.burn_engine.total_burned(),
            epoch_burned: self.burn_engine.epoch_burned(),
            current_rate_bps: self.burn_engine.current_rate_bps(),
            avg_utilization_bps: self.burn_engine.avg_utilization_bps(),
        }
    }

    /// Get emission schedule info
    pub fn emission_info(&self, current_time: u64) -> EmissionScheduleInfo {
        self.emission_calculator.schedule_info(current_time)
    }

    /// Get category statistics
    pub fn category_stats(&self, category: AllocationCategory) -> CategoryStats {
        self.category_stats
            .get(&category)
            .cloned()
            .unwrap_or_default()
    }

    /// Reset epoch (called at epoch boundary)
    pub fn reset_epoch(&mut self) {
        self.burn_engine.reset_epoch();
    }

    /// Drain events
    pub fn drain_events(&mut self) -> Vec<TokenomicsEvent> {
        std::mem::take(&mut self.events)
    }
}

/// Genesis allocation specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub beneficiary: Address,
    pub amount: TokenAmount,
    pub category: AllocationCategory,
    pub custom_schedule: Option<VestingSchedule>,
    pub revocable: bool,
}

/// Fee distribution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeDistribution {
    pub total_fee: TokenAmount,
    pub prover_amount: TokenAmount,
    pub validator_amount: TokenAmount,
    pub burn_amount: TokenAmount,
    pub effective_burn_rate_bps: u16,
}

/// Supply information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyInfo {
    pub total_supply: TokenAmount,
    pub circulating_supply: TokenAmount,
    pub total_burned: TokenAmount,
    pub total_locked: TokenAmount,
    pub total_vested: TokenAmount,
    pub mining_emitted: TokenAmount,
    pub mining_remaining: TokenAmount,
}

/// Burn statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnStats {
    pub total_burned: TokenAmount,
    pub epoch_burned: TokenAmount,
    pub current_rate_bps: u16,
    pub avg_utilization_bps: u16,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_allocation_totals() {
        let total = COMPUTE_POUW_POOL
            + CORE_CONTRIBUTORS_POOL
            + ECOSYSTEM_GRANTS_POOL
            + STRATEGIC_SEED_POOL
            + PUBLIC_SALES_POOL
            + AIRDROP_SEALS_POOL
            + TREASURY_MM_POOL
            + INSURANCE_FUND_POOL
            + CONTINGENCY_RESERVE_POOL;

        assert_eq!(total, TOTAL_GENESIS_SUPPLY);
    }

    #[test]
    fn test_allocation_percentages() {
        let total_bps: u16 = [
            AllocationCategory::ComputePoUW,
            AllocationCategory::CoreContributors,
            AllocationCategory::EcosystemGrants,
            AllocationCategory::StrategicSeed,
            AllocationCategory::PublicSales,
            AllocationCategory::AirdropSeals,
            AllocationCategory::TreasuryMM,
            AllocationCategory::InsuranceFund,
            AllocationCategory::ContingencyReserve,
        ]
        .iter()
        .map(|c| c.percentage_bps())
        .sum();

        assert_eq!(total_bps, 10000); // 100%
    }

    #[test]
    fn test_burn_rate_calculation() {
        let engine = AdaptiveBurnEngine::new(BurnConfig::default());

        // 0% utilization -> minimum burn
        let rate_0 = engine.calculate_burn_rate(0);
        assert_eq!(rate_0, MIN_BURN_RATE_BPS);

        // 100% utilization -> maximum burn
        let rate_100 = engine.calculate_burn_rate(10000);
        assert_eq!(rate_100, MAX_BURN_RATE_BPS);

        // 50% utilization -> should be about 8.75% (quadratic)
        let rate_50 = engine.calculate_burn_rate(5000);
        assert!(rate_50 > MIN_BURN_RATE_BPS);
        assert!(rate_50 < MAX_BURN_RATE_BPS);
        // 5% + (20% - 5%) * 0.25 = 5% + 3.75% = 8.75%
        assert!(rate_50 >= 800 && rate_50 <= 950);
    }

    #[test]
    fn test_linear_vesting() {
        let schedule = VestingSchedule::Linear {
            cliff: Duration::from_secs(SECONDS_PER_YEAR),
            duration: Duration::from_secs(3 * SECONDS_PER_YEAR),
            tge_percent: 10,
        };

        let total = 100 * ONE_AETHEL;
        let start = 1000;

        // At start: TGE amount only
        let vested_start = schedule.vested_amount(total, start, start);
        assert_eq!(vested_start, 10 * ONE_AETHEL);

        // During cliff: TGE amount only
        let during_cliff = start + SECONDS_PER_YEAR / 2;
        let vested_cliff = schedule.vested_amount(total, start, during_cliff);
        assert_eq!(vested_cliff, 10 * ONE_AETHEL);

        // After full duration: 100%
        let after_full = start + 3 * SECONDS_PER_YEAR + 1;
        let vested_full = schedule.vested_amount(total, start, after_full);
        assert_eq!(vested_full, total);
    }

    #[test]
    fn test_emission_halving() {
        let calc = EmissionCalculator::new(
            COMPUTE_POUW_POOL,
            HALVING_INTERVAL_SECS,
            TOTAL_EMISSION_DURATION_SECS,
            0,
        );

        // Initial rate
        let initial_rate = calc.current_rate_per_second(1);
        assert!(initial_rate > 0);

        // After 1 halving, rate should be half
        let rate_after_halving = calc.current_rate_per_second(HALVING_INTERVAL_SECS + 1);
        assert_eq!(rate_after_halving, initial_rate / 2);

        // After 2 halvings, rate should be quarter
        let rate_after_2_halvings = calc.current_rate_per_second(2 * HALVING_INTERVAL_SECS + 1);
        assert_eq!(rate_after_2_halvings, initial_rate / 4);
    }

    #[test]
    fn test_fee_distribution() {
        let config = TokenomicsConfig {
            adaptive_burn_enabled: false,
            prover_fee_bps: 7000,
            validator_fee_bps: 2000,
            burn_fee_bps: 1000,
            ..Default::default()
        };
        let mut manager = TokenomicsManager::new(config);

        let fee = 100 * ONE_AETHEL;
        let dist = manager.process_fee(fee, 5000);

        // With adaptive burn disabled, should use fixed rate
        assert_eq!(dist.burn_amount, 10 * ONE_AETHEL); // 10%
                                                       // Remaining 90 AETHEL split 70/20
                                                       // Actually: prover gets 70% of remaining, validator gets rest
                                                       // remaining = 90, prover = 63, validator = 27
        assert!(dist.prover_amount > 0);
        assert!(dist.validator_amount > 0);
        assert_eq!(
            dist.prover_amount + dist.validator_amount + dist.burn_amount,
            fee
        );
    }
}
