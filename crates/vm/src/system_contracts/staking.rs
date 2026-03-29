//! Staking Manager System Contract
//!
//! The economic engine for Aethelred - handles staking, slashing, rewards,
//! and the Adaptive Burn Mechanism.
//!
//! # Fee Distribution
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                      ADAPTIVE FEE SPLIT                                  │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   Job Fee ───────────────────────────────────────────────────────────►  │
//! │       │                                                                  │
//! │       ├──► Prover Reward (70%)                                          │
//! │       │                                                                  │
//! │       ├──► Validator Reward (15-25%)   ◄── Based on network load        │
//! │       │                                                                  │
//! │       └──► BURN (5-15%)                ◄── ADAPTIVE: Higher when busy   │
//! │                                                                          │
//! │   Network Utilization:                                                   │
//! │     < 50%  → Burn 5%,  Validator 25%                                    │
//! │     50-80% → Burn 10%, Validator 20%                                    │
//! │     > 80%  → Burn 15%, Validator 15%  (Congestion pricing)              │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use super::bank::Bank;
use super::error::{SystemContractError, SystemContractResult};
use super::events::StakingEvent;
use super::types::{Address, StakeRole, TokenAmount};
use super::BlockContext;

// =============================================================================
// STAKING CONFIGURATION
// =============================================================================

/// Staking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake for validators
    pub min_validator_stake: TokenAmount,
    /// Minimum stake for compute nodes
    pub min_compute_stake: TokenAmount,
    /// Minimum stake for delegators
    pub min_delegator_stake: TokenAmount,
    /// Unbonding period in seconds
    pub unbonding_period: u64,
    /// Base burn rate (basis points, 100 = 1%)
    pub base_burn_rate_bps: u16,
    /// Maximum burn rate
    pub max_burn_rate_bps: u16,
    /// Congestion threshold (percentage)
    pub congestion_threshold: u8,
    /// High congestion threshold
    pub high_congestion_threshold: u8,
    /// Slashing parameters
    pub slashing: SlashingParams,
    /// Maximum validators
    pub max_validators: u32,
    /// Maximum delegators per validator
    pub max_delegators_per_validator: u32,
}

impl StakingConfig {
    /// Mainnet configuration
    ///
    /// As per Aethelred Economic Specification:
    /// - Validator Node: 100,000 AETHEL minimum, 21-day unbonding
    /// - Compute Node: 5,000 AETHEL minimum, 7-day unbonding
    pub fn mainnet() -> Self {
        Self {
            // Validator: 100,000 AETHEL (high security requirement)
            // Rationale: Validators control consensus; they must have "skin in the game"
            min_validator_stake: 100_000_000_000_000_000_000_000, // 100,000 AETHEL

            // Compute Node: 5,000 AETHEL (lower barrier for workers)
            // Rationale: Lower barrier to encourage students/researchers to contribute GPU power
            min_compute_stake: 5_000_000_000_000_000_000_000, // 5,000 AETHEL

            // Delegator: 100 AETHEL
            min_delegator_stake: 100_000_000_000_000_000_000, // 100 AETHEL

            // Validator unbonding: 21 days
            unbonding_period: 21 * 24 * 3600, // 21 days

            // Adaptive burn: 5% base, 15% max
            base_burn_rate_bps: 500, // 5%
            max_burn_rate_bps: 1500, // 15%

            // Congestion thresholds
            congestion_threshold: 50,
            high_congestion_threshold: 80,

            slashing: SlashingParams::mainnet(),
            max_validators: 1000,
            max_delegators_per_validator: 10000,
        }
    }

    /// Testnet configuration (reduced stakes for testing)
    pub fn testnet() -> Self {
        Self {
            min_validator_stake: 10_000_000_000_000_000_000_000, // 10,000 AETHEL (1/10 mainnet)
            min_compute_stake: 500_000_000_000_000_000_000,      // 500 AETHEL (1/10 mainnet)
            min_delegator_stake: 10_000_000_000_000_000_000,     // 10 AETHEL
            unbonding_period: 7 * 24 * 3600,                     // 7 days
            base_burn_rate_bps: 300,
            max_burn_rate_bps: 1000,
            congestion_threshold: 40,
            high_congestion_threshold: 70,
            slashing: SlashingParams::testnet(),
            max_validators: 200,
            max_delegators_per_validator: 1000,
        }
    }

    /// Devnet configuration
    pub fn devnet() -> Self {
        Self {
            min_validator_stake: 1_000_000_000_000_000_000, // 1 AETHEL
            min_compute_stake: 1_000_000_000_000_000_000,   // 1 AETHEL
            min_delegator_stake: 100_000_000_000_000_000,   // 0.1 AETHEL
            unbonding_period: 60,                           // 1 minute
            base_burn_rate_bps: 500,
            max_burn_rate_bps: 1500,
            congestion_threshold: 50,
            high_congestion_threshold: 80,
            slashing: SlashingParams::devnet(),
            max_validators: 100,
            max_delegators_per_validator: 100,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> SystemContractResult<()> {
        if self.min_validator_stake == 0 {
            return Err(SystemContractError::InvalidConfig(
                "min_validator_stake must be > 0".into(),
            ));
        }
        if self.base_burn_rate_bps > self.max_burn_rate_bps {
            return Err(SystemContractError::InvalidConfig(
                "base_burn_rate_bps must be <= max_burn_rate_bps".into(),
            ));
        }
        if self.congestion_threshold >= self.high_congestion_threshold {
            return Err(SystemContractError::InvalidConfig(
                "congestion_threshold must be < high_congestion_threshold".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// SLASHING PARAMETERS
// =============================================================================

/// Slashing parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingParams {
    /// Slash rate for SLA violations (basis points)
    pub sla_violation_bps: u16,
    /// Slash rate for invalid proofs
    pub invalid_proof_bps: u16,
    /// Slash rate for double signing
    pub double_sign_bps: u16,
    /// Slash rate for downtime
    pub downtime_bps: u16,
    /// Jail duration for minor offenses (seconds)
    pub minor_jail_duration: u64,
    /// Jail duration for major offenses
    pub major_jail_duration: u64,
    /// Tombstone threshold (permanent removal)
    pub tombstone_threshold: u32,
}

impl SlashingParams {
    pub fn mainnet() -> Self {
        Self {
            sla_violation_bps: 100,             // 1%
            invalid_proof_bps: 500,             // 5%
            double_sign_bps: 5000,              // 50%
            downtime_bps: 10,                   // 0.1%
            minor_jail_duration: 24 * 3600,     // 1 day
            major_jail_duration: 7 * 24 * 3600, // 1 week
            tombstone_threshold: 10,            // 10 major offenses
        }
    }

    pub fn testnet() -> Self {
        Self {
            sla_violation_bps: 50,
            invalid_proof_bps: 200,
            double_sign_bps: 2000,
            downtime_bps: 5,
            minor_jail_duration: 3600,
            major_jail_duration: 24 * 3600,
            tombstone_threshold: 5,
        }
    }

    pub fn devnet() -> Self {
        Self {
            sla_violation_bps: 10,
            invalid_proof_bps: 50,
            double_sign_bps: 500,
            downtime_bps: 1,
            minor_jail_duration: 60,
            major_jail_duration: 300,
            tombstone_threshold: 3,
        }
    }
}

// =============================================================================
// FEE SPLIT
// =============================================================================

/// Fee split result
#[derive(Debug, Clone, Copy)]
pub struct FeeSplit {
    /// Amount to prover
    pub prover: TokenAmount,
    /// Amount to validator
    pub validator: TokenAmount,
    /// Amount to burn
    pub burn: TokenAmount,
}

// =============================================================================
// STAKE INFO
// =============================================================================

/// Staker information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    /// Staker address
    pub address: Address,
    /// Stake role
    pub role: StakeRole,
    /// Total staked amount
    pub staked: TokenAmount,
    /// Amount in unbonding
    pub unbonding: TokenAmount,
    /// Unbonding completion time
    pub unbonding_complete_time: u64,
    /// Slashing count
    pub slash_count: u32,
    /// Jailed until timestamp (0 = not jailed)
    pub jailed_until: u64,
    /// Tombstoned (permanently removed)
    pub tombstoned: bool,
    /// Total rewards earned
    pub total_rewards: TokenAmount,
    /// Registration timestamp
    pub registered_at: u64,
    /// Delegations (for validators)
    pub delegators: Vec<Delegation>,
    /// Useful work score (for compute nodes, from reputation)
    pub useful_work_score: u64,
}

impl StakeInfo {
    /// Create new stake info
    pub fn new(address: Address, role: StakeRole, amount: TokenAmount, timestamp: u64) -> Self {
        Self {
            address,
            role,
            staked: amount,
            unbonding: 0,
            unbonding_complete_time: 0,
            slash_count: 0,
            jailed_until: 0,
            tombstoned: false,
            total_rewards: 0,
            registered_at: timestamp,
            delegators: Vec::new(),
            useful_work_score: 0,
        }
    }

    /// Check if staker is active (not jailed or tombstoned)
    pub fn is_active(&self, current_time: u64) -> bool {
        !self.tombstoned && self.jailed_until <= current_time
    }

    /// Get effective stake (including delegations for validators)
    pub fn effective_stake(&self) -> TokenAmount {
        let delegation_total: TokenAmount = self.delegators.iter().map(|d| d.amount).sum();
        self.staked + delegation_total
    }
}

/// Delegation info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Delegator address
    pub delegator: Address,
    /// Delegated amount
    pub amount: TokenAmount,
    /// Delegation timestamp
    pub delegated_at: u64,
}

// =============================================================================
// STAKING MANAGER
// =============================================================================

/// Staking Manager - economic engine
pub struct StakingManager {
    /// Configuration
    config: StakingConfig,

    /// Bank reference for token operations
    bank: Arc<RwLock<Bank>>,

    /// Stakers by address
    stakers: HashMap<Address, StakeInfo>,

    /// Total staked
    total_staked: TokenAmount,

    /// Total burned
    total_burned: TokenAmount,

    /// Network utilization (0-100)
    network_utilization: u8,

    /// Current burn rate (basis points)
    current_burn_rate_bps: u16,

    /// Event queue
    events: Vec<StakingEvent>,

    /// Current block height
    current_block: u64,
}

impl StakingManager {
    /// Create new staking manager
    pub fn new(config: StakingConfig, bank: Arc<RwLock<Bank>>) -> Self {
        Self {
            current_burn_rate_bps: config.base_burn_rate_bps,
            config,
            bank,
            stakers: HashMap::new(),
            total_staked: 0,
            total_burned: 0,
            network_utilization: 0,
            events: Vec::new(),
            current_block: 0,
        }
    }

    /// Get and clear pending events
    pub fn drain_events(&mut self) -> Vec<StakingEvent> {
        std::mem::take(&mut self.events)
    }

    // =========================================================================
    // ADAPTIVE BURN MECHANISM
    // =========================================================================

    /// Update network utilization and adjust burn rate
    pub fn update_utilization(&mut self, utilization: u8) {
        let old_utilization = self.network_utilization;
        self.network_utilization = utilization.min(100);

        // Calculate new burn rate based on congestion
        let new_burn_rate = if utilization > self.config.high_congestion_threshold {
            // High congestion: maximum burn
            self.config.max_burn_rate_bps
        } else if utilization > self.config.congestion_threshold {
            // Medium congestion: interpolate
            let range = self.config.max_burn_rate_bps - self.config.base_burn_rate_bps;
            let congestion_range =
                self.config.high_congestion_threshold - self.config.congestion_threshold;
            let excess = utilization - self.config.congestion_threshold;
            let additional = (range as u32 * excess as u32 / congestion_range as u32) as u16;
            self.config.base_burn_rate_bps + additional
        } else {
            // Low congestion: base burn
            self.config.base_burn_rate_bps
        };

        if new_burn_rate != self.current_burn_rate_bps {
            self.current_burn_rate_bps = new_burn_rate;

            self.events.push(StakingEvent::UtilizationUpdated {
                old_utilization,
                new_utilization: self.network_utilization,
                new_burn_rate: self.current_burn_rate_bps as u8,
                block_height: self.current_block,
            });
        }
    }

    /// Calculate fee split based on current network conditions
    ///
    /// This implements the "Congestion Pricing" mechanism:
    /// - Prover always gets 70%
    /// - Burn rate varies from 5-15% based on utilization
    /// - Validator gets the remainder (15-25%)
    pub fn calculate_fee_split(&self, fee: TokenAmount) -> (TokenAmount, TokenAmount, TokenAmount) {
        // Prover always gets 70%
        let prover_amount = (fee * 70) / 100;

        // Burn amount based on current rate
        let burn_amount = (fee * self.current_burn_rate_bps as u128) / 10000;

        // Validator gets remainder
        let validator_amount = fee
            .saturating_sub(prover_amount)
            .saturating_sub(burn_amount);

        (prover_amount, validator_amount, burn_amount)
    }

    // =========================================================================
    // STAKING OPERATIONS
    // =========================================================================

    /// Stake tokens
    pub fn stake(
        &mut self,
        staker: Address,
        amount: TokenAmount,
        role: StakeRole,
        bank: &mut Bank,
    ) -> SystemContractResult<()> {
        // 1. Check minimum stake
        let min_stake = match role {
            StakeRole::Validator => self.config.min_validator_stake,
            StakeRole::ComputeNode => self.config.min_compute_stake,
            StakeRole::Delegator => self.config.min_delegator_stake,
        };

        if amount < min_stake {
            return Err(SystemContractError::InsufficientStake {
                required: min_stake,
                actual: amount,
            });
        }

        // 2. Lock tokens in bank
        bank.lock(&staker, amount)?;

        // 3. Update or create stake info
        let info = self
            .stakers
            .entry(staker)
            .or_insert_with(|| StakeInfo::new(staker, role, 0, self.current_block));

        info.staked = info.staked.saturating_add(amount);
        self.total_staked = self.total_staked.saturating_add(amount);

        // 4. Emit event
        self.events.push(StakingEvent::Staked {
            staker,
            amount,
            role,
            total_stake: info.staked,
            block_height: self.current_block,
        });

        Ok(())
    }

    /// Initiate unstaking
    pub fn unstake(
        &mut self,
        staker: Address,
        amount: TokenAmount,
        ctx: &BlockContext,
    ) -> SystemContractResult<()> {
        let info = self
            .stakers
            .get_mut(&staker)
            .ok_or_else(|| SystemContractError::staker_not_found(&staker))?;

        // 1. Check not jailed
        if info.jailed_until > ctx.timestamp {
            return Err(SystemContractError::SlashingInProgress);
        }

        // 2. Check has enough staked
        let available = info.staked.saturating_sub(info.unbonding);
        if available < amount {
            return Err(SystemContractError::CannotUnstake {
                requested: amount,
                available,
            });
        }

        // 3. Check minimum stake maintained
        let remaining = info.staked.saturating_sub(amount);
        let min_stake = match info.role {
            StakeRole::Validator => self.config.min_validator_stake,
            StakeRole::ComputeNode => self.config.min_compute_stake,
            StakeRole::Delegator => self.config.min_delegator_stake,
        };

        if remaining > 0 && remaining < min_stake {
            return Err(SystemContractError::InsufficientStake {
                required: min_stake,
                actual: remaining,
            });
        }

        // 4. Start unbonding
        info.unbonding = info.unbonding.saturating_add(amount);
        info.unbonding_complete_time = ctx.timestamp + self.config.unbonding_period;

        // 5. Emit event
        self.events.push(StakingEvent::UnstakeInitiated {
            staker,
            amount,
            unlock_time: info.unbonding_complete_time,
            block_height: ctx.height,
        });

        Ok(())
    }

    /// Withdraw unbonded stake
    pub fn withdraw(
        &mut self,
        staker: Address,
        ctx: &BlockContext,
        bank: &mut Bank,
    ) -> SystemContractResult<TokenAmount> {
        let info = self
            .stakers
            .get_mut(&staker)
            .ok_or_else(|| SystemContractError::staker_not_found(&staker))?;

        // 1. Check unbonding is complete
        if info.unbonding == 0 {
            return Err(SystemContractError::NothingToWithdraw);
        }

        if info.unbonding_complete_time > ctx.timestamp {
            return Err(SystemContractError::UnstakeInProgress {
                unlock_time: info.unbonding_complete_time,
            });
        }

        // 2. Process withdrawal
        let amount = info.unbonding;
        info.staked = info.staked.saturating_sub(amount);
        info.unbonding = 0;
        info.unbonding_complete_time = 0;

        self.total_staked = self.total_staked.saturating_sub(amount);

        // 3. Unlock tokens
        bank.unlock(&staker, amount)?;

        // 4. Emit event
        self.events.push(StakingEvent::StakeWithdrawn {
            staker,
            amount,
            block_height: ctx.height,
        });

        Ok(amount)
    }

    // =========================================================================
    // SLASHING
    // =========================================================================

    /// Slash for SLA violation
    pub fn slash_for_sla_violation(
        &mut self,
        staker: &Address,
    ) -> SystemContractResult<TokenAmount> {
        self.slash(
            staker,
            self.config.slashing.sla_violation_bps,
            "SLA violation",
            true,
        )
    }

    /// Slash for invalid proof
    pub fn slash_for_invalid_proof(
        &mut self,
        staker: &Address,
    ) -> SystemContractResult<TokenAmount> {
        self.slash(
            staker,
            self.config.slashing.invalid_proof_bps,
            "Invalid proof",
            true,
        )
    }

    /// Slash for double signing
    pub fn slash_for_double_sign(&mut self, staker: &Address) -> SystemContractResult<TokenAmount> {
        self.slash(
            staker,
            self.config.slashing.double_sign_bps,
            "Double signing",
            true,
        )
    }

    /// Generic slash operation
    fn slash(
        &mut self,
        staker: &Address,
        rate_bps: u16,
        reason: &str,
        jail: bool,
    ) -> SystemContractResult<TokenAmount> {
        let info = self
            .stakers
            .get_mut(staker)
            .ok_or_else(|| SystemContractError::staker_not_found(staker))?;

        // Calculate slash amount
        let slash_amount = (info.staked * rate_bps as u128) / 10000;

        // Apply slash via bank
        let actual_slashed = {
            let mut bank = self.bank.write();
            bank.slash(staker, slash_amount)?
        };

        info.staked = info.staked.saturating_sub(actual_slashed);
        info.slash_count += 1;
        self.total_staked = self.total_staked.saturating_sub(actual_slashed);
        self.total_burned = self.total_burned.saturating_add(actual_slashed);

        // Jail if required
        if jail {
            let jail_duration = if rate_bps >= self.config.slashing.double_sign_bps {
                self.config.slashing.major_jail_duration
            } else {
                self.config.slashing.minor_jail_duration
            };
            info.jailed_until = self.current_block + jail_duration;

            self.events.push(StakingEvent::ValidatorJailed {
                validator: *staker,
                reason: reason.into(),
                until: info.jailed_until,
                block_height: self.current_block,
            });
        }

        // Check for tombstone
        if info.slash_count >= self.config.slashing.tombstone_threshold {
            info.tombstoned = true;
        }

        // Emit slash event
        self.events.push(StakingEvent::Slashed {
            staker: *staker,
            amount: actual_slashed,
            reason: reason.into(),
            job_id: None,
            block_height: self.current_block,
        });

        Ok(actual_slashed)
    }

    // =========================================================================
    // REWARDS
    // =========================================================================

    /// Distribute rewards to a prover
    pub fn distribute_rewards(
        &mut self,
        fee: TokenAmount,
        prover: Address,
        validator: Address,
    ) -> SystemContractResult<FeeSplit> {
        let (prover_amount, validator_amount, burn_amount) = self.calculate_fee_split(fee);

        // Track rewards
        if let Some(info) = self.stakers.get_mut(&prover) {
            info.total_rewards = info.total_rewards.saturating_add(prover_amount);
        }

        if let Some(info) = self.stakers.get_mut(&validator) {
            info.total_rewards = info.total_rewards.saturating_add(validator_amount);
        }

        // Track burned
        self.total_burned = self.total_burned.saturating_add(burn_amount);

        // Emit events
        self.events.push(StakingEvent::RewardsDistributed {
            staker: prover,
            amount: prover_amount,
            source: "job_completion".into(),
            block_height: self.current_block,
        });

        self.events.push(StakingEvent::RewardsDistributed {
            staker: validator,
            amount: validator_amount,
            source: "block_proposal".into(),
            block_height: self.current_block,
        });

        self.events.push(StakingEvent::TokensBurned {
            amount: burn_amount,
            reason: "fee_burn".into(),
            block_height: self.current_block,
        });

        Ok(FeeSplit {
            prover: prover_amount,
            validator: validator_amount,
            burn: burn_amount,
        })
    }

    // =========================================================================
    // END OF BLOCK
    // =========================================================================

    /// Process end of block operations
    pub fn end_block(&mut self, ctx: &BlockContext) -> SystemContractResult<Vec<StakingEvent>> {
        self.current_block = ctx.height;

        // Auto-unjail validators whose jail period has ended
        for info in self.stakers.values_mut() {
            if info.jailed_until > 0 && info.jailed_until <= ctx.timestamp && !info.tombstoned {
                info.jailed_until = 0;
                self.events.push(StakingEvent::ValidatorUnjailed {
                    validator: info.address,
                    block_height: ctx.height,
                });
            }
        }

        Ok(self.drain_events())
    }

    // =========================================================================
    // QUERIES
    // =========================================================================

    /// Get staker info
    pub fn get_staker(&self, address: &Address) -> Option<&StakeInfo> {
        self.stakers.get(address)
    }

    /// Get total staked
    pub fn total_staked(&self) -> TokenAmount {
        self.total_staked
    }

    /// Get total burned
    pub fn total_burned(&self) -> TokenAmount {
        self.total_burned
    }

    /// Get current burn rate
    pub fn current_burn_rate(&self) -> u16 {
        self.current_burn_rate_bps
    }

    /// Get network utilization
    pub fn network_utilization(&self) -> u8 {
        self.network_utilization
    }

    /// Get all validators
    pub fn validators(&self) -> Vec<&StakeInfo> {
        self.stakers
            .values()
            .filter(|s| matches!(s.role, StakeRole::Validator))
            .collect()
    }

    /// Get all compute nodes
    pub fn compute_nodes(&self) -> Vec<&StakeInfo> {
        self.stakers
            .values()
            .filter(|s| matches!(s.role, StakeRole::ComputeNode))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> StakingStats {
        let validators = self.validators();
        let compute_nodes = self.compute_nodes();

        StakingStats {
            total_staked: self.total_staked,
            total_burned: self.total_burned,
            validator_count: validators.len() as u32,
            compute_node_count: compute_nodes.len() as u32,
            network_utilization: self.network_utilization,
            current_burn_rate_bps: self.current_burn_rate_bps,
        }
    }
}

/// Staking statistics
#[derive(Debug, Clone)]
pub struct StakingStats {
    pub total_staked: TokenAmount,
    pub total_burned: TokenAmount,
    pub validator_count: u32,
    pub compute_node_count: u32,
    pub network_utilization: u8,
    pub current_burn_rate_bps: u16,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_contracts::bank::BankConfig;

    fn setup() -> (StakingManager, Arc<RwLock<Bank>>) {
        let bank = Arc::new(RwLock::new(Bank::new(BankConfig::default())));

        // Give test account balance
        {
            let mut b = bank.write();
            b.mint([1u8; 32], 1_000_000_000_000_000_000_000_000)
                .expect("mint should succeed"); // 1M AETHEL
        }

        let manager = StakingManager::new(StakingConfig::devnet(), bank.clone());
        (manager, bank)
    }

    #[test]
    fn test_fee_split_base() {
        let (manager, _) = setup();

        let fee = 1000u128;
        let (prover, validator, burn) = manager.calculate_fee_split(fee);

        assert_eq!(prover, 700); // 70%
        assert_eq!(burn, 50); // 5% base
        assert_eq!(validator, 250); // Remainder
        assert_eq!(prover + validator + burn, fee);
    }

    #[test]
    fn test_adaptive_burn() {
        let (mut manager, _) = setup();

        // Low utilization
        manager.update_utilization(30);
        let (_, _, burn_low) = manager.calculate_fee_split(1000);

        // High utilization
        manager.update_utilization(90);
        let (_, _, burn_high) = manager.calculate_fee_split(1000);

        // High congestion should burn more
        assert!(burn_high > burn_low);
    }

    #[test]
    fn test_stake_unstake() {
        let (mut manager, bank) = setup();

        let ctx = BlockContext {
            height: 100,
            timestamp: 1000,
            slot: 100,
            proposer: [10u8; 32],
            gas_limit: 30_000_000,
            gas_used: 0,
        };

        // Stake
        {
            let mut b = bank.write();
            manager
                .stake(
                    [1u8; 32],
                    2_000_000_000_000_000_000,
                    StakeRole::Validator,
                    &mut b,
                )
                .unwrap();
        }

        let info = manager.get_staker(&[1u8; 32]).unwrap();
        assert_eq!(info.staked, 2_000_000_000_000_000_000);

        // Initiate unstake
        manager
            .unstake([1u8; 32], 1_000_000_000_000_000_000, &ctx)
            .unwrap();

        let info = manager.get_staker(&[1u8; 32]).unwrap();
        assert_eq!(info.unbonding, 1_000_000_000_000_000_000);
    }

    #[test]
    fn test_slashing() {
        let (mut manager, bank) = setup();

        // Stake first
        {
            let mut b = bank.write();
            manager
                .stake(
                    [1u8; 32],
                    1_000_000_000_000_000_000,
                    StakeRole::Validator,
                    &mut b,
                )
                .unwrap();
        }

        // Slash
        let slashed = manager.slash_for_sla_violation(&[1u8; 32]).unwrap();
        assert!(slashed > 0);

        let info = manager.get_staker(&[1u8; 32]).unwrap();
        assert!(info.jailed_until > 0);
        assert_eq!(info.slash_count, 1);
    }

    #[test]
    fn test_utilization_burn_rate() {
        let config = StakingConfig::mainnet();
        let bank = Arc::new(RwLock::new(Bank::new(BankConfig::default())));
        let mut manager = StakingManager::new(config.clone(), bank);

        // Below threshold
        manager.update_utilization(40);
        assert_eq!(manager.current_burn_rate(), config.base_burn_rate_bps);

        // At high threshold
        manager.update_utilization(85);
        assert_eq!(manager.current_burn_rate(), config.max_burn_rate_bps);

        // In between
        manager.update_utilization(65);
        assert!(manager.current_burn_rate() > config.base_burn_rate_bps);
        assert!(manager.current_burn_rate() < config.max_burn_rate_bps);
    }
}
