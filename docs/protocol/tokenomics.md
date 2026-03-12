# Tokenomics: AETHEL Token Economics

<p align="center">
  <strong>Aethelred Token Economic Model</strong><br/>
  <em>Version 2.0.0 | February 2026</em>
</p>

---

## Document Information

| Attribute | Value |
|-----------|-------|
| **Version** | 2.0.0 |
| **Status** | Approved for Engineering Implementation |
| **Classification** | Confidential - Authorized Personnel Only |
| **Effective Date** | February 2026 |
| **Document Owner** | Aethelred Protocol Foundation |
| **Economic Review** | Gauntlet Network (Q4 2025) |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Token Overview](#2-token-overview)
3. [Token Distribution](#3-token-distribution)
4. [Utility Functions](#4-utility-functions)
5. [Fee Mechanism](#5-fee-mechanism)
6. [Staking Economics](#6-staking-economics)
7. [Emission and Deflation](#7-emission-and-deflation)
8. [Governance Token](#8-governance-token)
9. [Economic Security](#9-economic-security)
10. [Long-Term Sustainability](#10-long-term-sustainability)
11. [Technical Integration Priorities](#11-technical-integration-priorities)

---

## 1. Executive Summary

### 1.1 Key Metrics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AETHEL TOKEN OVERVIEW                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TOKEN FUNDAMENTALS                                                    │  │
│  │                                                                        │  │
│  │  Name:           AETHEL                                               │  │
│  │  Symbol:         AETHEL                                               │  │
│  │  Decimals:       18                                                   │  │
│  │  Chain ID:       8821                                                 │  │
│  │  Standard:       Native Token (not ERC-20)                            │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  SUPPLY METRICS                                                        │  │
│  │                                                                        │  │
│  │  Genesis Supply:     10,000,000,000 AETHEL                            │  │
│  │  Max Supply:         10,000,000,000 AETHEL (hard capped)              │  │
│  │  Tail Emissions:     None                                              │  │
│  │  Burn Mechanism:     Congestion-Squared (deflationary pressure)       │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  ECONOMIC MODEL                                                        │  │
│  │                                                                        │  │
│  │  Consensus:      Proof of Useful Work (PoUW)                          │  │
│  │  Fee Model:      Base Fee + Priority Fee                              │  │
│  │  Burn Rate:      Fee × Congestion² (EIP-1559 inspired)                │  │
│  │  Staking Yield:  5-15% APY (variable based on stake ratio)            │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Value Accrual Thesis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VALUE ACCRUAL MECHANISM                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                          ┌───────────────────┐                              │
│                          │  ENTERPRISE AI    │                              │
│                          │    ADOPTION       │                              │
│                          └─────────┬─────────┘                              │
│                                    │                                         │
│                                    ▼                                         │
│                          ┌───────────────────┐                              │
│                          │  COMPUTE JOBS     │                              │
│                          │  (Paid in AETHEL) │                              │
│                          └─────────┬─────────┘                              │
│                                    │                                         │
│                    ┌───────────────┼───────────────┐                        │
│                    │               │               │                        │
│                    ▼               ▼               ▼                        │
│           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐               │
│           │   VALIDATOR  │ │    FEE       │ │   TREASURY   │               │
│           │   REWARDS    │ │    BURN      │ │   ALLOCATION │               │
│           │    (70%)     │ │    (25%)     │ │     (5%)     │               │
│           └──────────────┘ └──────────────┘ └──────────────┘               │
│                    │               │               │                        │
│                    ▼               ▼               ▼                        │
│           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐               │
│           │   STAKING    │ │  DEFLATION   │ │  ECOSYSTEM   │               │
│           │   INCENTIVE  │ │  PRESSURE    │ │   GROWTH     │               │
│           └──────────────┘ └──────────────┘ └──────────────┘               │
│                    │               │               │                        │
│                    └───────────────┼───────────────┘                        │
│                                    │                                         │
│                                    ▼                                         │
│                          ┌───────────────────┐                              │
│                          │  TOKEN VALUE      │                              │
│                          │  APPRECIATION     │                              │
│                          └───────────────────┘                              │
│                                                                              │
│  FLYWHEEL EFFECT:                                                           │
│  More adoption → More compute jobs → More fees → More burn → Less supply   │
│  Less supply → Higher price → More validator incentive → Better service    │
│  Better service → More adoption → (cycle repeats)                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Token Overview

### 2.1 Token Properties

```rust
/// AETHEL Token Constants
pub mod token {
    /// Token name
    pub const NAME: &str = "Aethelred";

    /// Token symbol
    pub const SYMBOL: &str = "AETHEL";

    /// Decimal places (same as Ethereum for compatibility)
    pub const DECIMALS: u8 = 18;

    /// One AETHEL in base units (wei equivalent)
    pub const ONE_AETHEL: u128 = 1_000_000_000_000_000_000; // 10^18

    /// Minimum transferable amount
    pub const MIN_TRANSFER: u128 = 1; // 1 wei

    /// Genesis supply (10 billion AETHEL, hard capped)
    pub const GENESIS_SUPPLY: u128 = 10_000_000_000 * ONE_AETHEL;

    /// Maximum supply (hard cap)
    pub const MAX_SUPPLY: u128 = 10_000_000_000 * ONE_AETHEL;

    /// Chain ID (Aethelred mainnet)
    pub const CHAIN_ID: u64 = 8821;

    /// Testnet Chain ID
    pub const TESTNET_CHAIN_ID: u64 = 88210;
}
```

### 2.2 Token Contract (Native)

Unlike ERC-20 tokens, AETHEL is the **native token** of the Aethelred L1. It is managed directly by the protocol, not a smart contract.

```rust
/// Native token balance tracking
pub struct TokenModule {
    /// Account balances
    balances: Storage<Address, Balance>,

    /// Total supply (including scheduled emissions)
    total_supply: Storage<Balance>,

    /// Burned tokens (cumulative)
    total_burned: Storage<Balance>,

    /// Lock manager for staking and vesting
    locks: LockManager,
}

impl TokenModule {
    /// Transfer tokens between accounts
    pub fn transfer(
        &mut self,
        ctx: &mut Context,
        from: &Address,
        to: &Address,
        amount: Balance,
    ) -> Result<(), TokenError> {
        // Check sufficient balance
        let from_balance = self.balances.get(from).unwrap_or_default();
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Check for locks (staking, vesting)
        let available = self.locks.available_balance(from, from_balance)?;
        if available < amount {
            return Err(TokenError::InsufficientUnlockedBalance);
        }

        // Execute transfer
        self.balances.set(from, from_balance - amount);
        let to_balance = self.balances.get(to).unwrap_or_default();
        self.balances.set(to, to_balance + amount);

        // Emit event
        ctx.emit_event(TransferEvent {
            from: *from,
            to: *to,
            amount,
        });

        Ok(())
    }

    /// Mint tokens from scheduled emission pools (called by consensus)
    pub fn mint(
        &mut self,
        ctx: &mut Context,
        to: &Address,
        amount: Balance,
    ) -> Result<(), TokenError> {
        // Only callable by consensus module
        ctx.require_caller(CONSENSUS_MODULE)?;

        // Update balance
        let balance = self.balances.get(to).unwrap_or_default();
        self.balances.set(to, balance + amount);

        // Update total supply
        let supply = self.total_supply.get().unwrap_or(GENESIS_SUPPLY);
        self.total_supply.set(supply + amount);

        ctx.emit_event(MintEvent { to: *to, amount });

        Ok(())
    }

    /// Burn tokens (fee burn, called by fee module)
    pub fn burn(
        &mut self,
        ctx: &mut Context,
        from: &Address,
        amount: Balance,
    ) -> Result<(), TokenError> {
        // Only callable by fee module
        ctx.require_caller(FEE_MODULE)?;

        // Check balance
        let balance = self.balances.get(from).unwrap_or_default();
        if balance < amount {
            return Err(TokenError::InsufficientBalance);
        }

        // Burn tokens
        self.balances.set(from, balance - amount);

        // Update tracking
        let supply = self.total_supply.get().unwrap_or(GENESIS_SUPPLY);
        self.total_supply.set(supply - amount);

        let burned = self.total_burned.get().unwrap_or_default();
        self.total_burned.set(burned + amount);

        ctx.emit_event(BurnEvent {
            from: *from,
            amount,
        });

        Ok(())
    }
}
```

---

## 3. Token Distribution

### 3.1 Genesis Distribution

**Total Supply: 10,000,000,000 AETHEL (Hard Capped)**

| Category | % | Token Amount | Notes |
|----------|---|--------------|-------|
| PoUW Rewards | 30% | 3,000,000,000 | Validator incentives (10-year program) |
| Core Contributors | 20% | 2,000,000,000 | Team alignment |
| Ecosystem & Grants | 15% | 1,500,000,000 | Developer adoption & dApp grants |
| Public Sales | 7.5% | 750,000,000 | Echo + Exchange sales |
| Airdrop (Seals) | 7% | 700,000,000 | Community incentives |
| Treasury & MM | 6% | 600,000,000 | Operational runway + Market Maker loans |
| Strategic / Seed | 5.5% | 550,000,000 | Seed + Strategic investors |
| Insurance Fund | 5% | 500,000,000 | Slashing appeals & hack indemnification |
| Contingency Reserve | 4% | 400,000,000 | Unknown unknowns; strategic pivots |
| **TOTAL** | **100%** | **10,000,000,000** | **Math verified** |

### 3.2 Vesting Schedules

**Compute / PoUW Rewards (30% - 3B tokens)**
- No cliff, no TGE unlock - rewards begin at genesis
- 10-year linear release (120 months, ~25M/month)
- Validator incentives for H100/TEE operators

**Core Contributors (20% - 2B tokens)**
- 6-month cliff, 15% released at cliff (300M)
- 5-year total vest (60 months), 42 months linear post-cliff (~41.7M/month)
- Team alignment; 6-month cliff for operational liquidity

**Ecosystem & Grants (15% - 1.5B tokens)**
- 2% TGE unlock (30M tokens at genesis)
- 6-month cliff, then 48 months linear post-cliff (~23.75M/month)
- 54 months total vest
- Developer adoption, dApp incentives

**Treasury & MM (6% - 600M tokens)**
- No cliff, 25% TGE unlock (150M tokens)
- 3-year total vest (36 months), linear (~12.5M/month)
- Operational runway + Market Maker loans (Wintermute, GSR)

**Public Sales (7.5% - 750M tokens)**
- 20% TGE unlock (150M tokens)
- No cliff, 18 months linear (~29.2M/month)
- Echo + Exchange sales; 80% locked

**Airdrop / Seals (7% - 700M tokens)**
- 25% TGE unlock (175M tokens)
- No cliff, 12 months linear (~43.75M/month)
- Points program starts Mar 2026; snapshot Nov 2026

**Strategic / Seed (5.5% - 550M tokens)**
- 12-month cliff, no TGE unlock
- 36 months total (12 cliff + 24 linear, ~22.9M/month)
- Seed + Strategic investor rounds

**Insurance Fund (5% - 500M tokens)**
- 10% TGE unlock (50M tokens)
- No cliff, 30 months linear (~12.5M/month)
- Max 10M per incident; 3-of-5 multi-sig governance

**Contingency Reserve (4% - 400M tokens)**
- No TGE unlock, 12-month cliff
- Vesting TBD; team + advisor majority vote; 30-day timelock
- Reserved for unforeseen circumstances, emergency funding, strategic pivots

**TGE Unlock Summary: 6.3% of total supply (630M tokens)**
- TGE market cap: $63M at $0.10/token

### 3.3 Strategic Characteristics

- **Insider allocation** (Core Contributors + Strategic/Seed) = **25.5%** (Tier-1 standard range)
- **Compute allocation** (**30%**) - protocol infrastructure engine, 10-year program for H100 validators
- **Ecosystem + Treasury** (**21%**) - growth and venture multiplier with staggered cliff schedules
- **Community float** (**14.5%**) - Public Sales (7.5%) + Airdrop/Seals (7%), broad participation with 20% / 25% TGE
- **Insurance + Contingency** (**9%**) - institutional trust, risk buffer, 10% insurance TGE for launch readiness
- **TGE circulating supply**: ~6.3% (630M tokens) - float for price discovery at $63M market cap ($0.10/token)

### 3.4 Clarification of Final Model

Earlier drafts discussed:
1. 1B supply
2. Tail emissions
3. Different vesting models
4. Different public unlock ratios
5. 10%/5% Investor/Public Sale split
6. 8-category allocation (now 9 categories)

The final approved model is the 10B hard-capped structure above with a 5.5%/7.5% Strategic-Seed/Public Sales split, a new 7% Airdrop (Seals) category, and supersedes those earlier drafts.

### 3.5 Vesting Contract

```rust
/// Vesting contract for token lockups
pub struct VestingSchedule {
    /// Beneficiary address
    pub beneficiary: Address,

    /// Total amount vested
    pub total_amount: Balance,

    /// Cliff duration (seconds)
    pub cliff_duration: u64,

    /// Total vesting duration (seconds)
    pub vesting_duration: u64,

    /// Start timestamp
    pub start_time: u64,

    /// Amount already claimed
    pub claimed: Balance,

    /// Whether vesting is revocable
    pub revocable: bool,
}

impl VestingSchedule {
    /// Calculate vested amount at current time
    pub fn vested_amount(&self, current_time: u64) -> Balance {
        if current_time < self.start_time + self.cliff_duration {
            // Still in cliff period
            return 0;
        }

        let elapsed = current_time - self.start_time;

        if elapsed >= self.vesting_duration {
            // Fully vested
            return self.total_amount;
        }

        // Linear vesting
        let vested = (self.total_amount as u128 * elapsed as u128
            / self.vesting_duration as u128) as Balance;

        vested
    }

    /// Calculate claimable amount
    pub fn claimable(&self, current_time: u64) -> Balance {
        let vested = self.vested_amount(current_time);
        vested.saturating_sub(self.claimed)
    }

    /// Claim vested tokens
    pub fn claim(&mut self, ctx: &mut Context) -> Result<Balance, VestingError> {
        let current_time = ctx.block_time();
        let claimable = self.claimable(current_time);

        if claimable == 0 {
            return Err(VestingError::NothingToClaim);
        }

        self.claimed += claimable;

        // Transfer tokens to beneficiary
        ctx.token_module().transfer(
            &VESTING_CONTRACT,
            &self.beneficiary,
            claimable,
        )?;

        ctx.emit_event(VestedClaimEvent {
            beneficiary: self.beneficiary,
            amount: claimable,
        });

        Ok(claimable)
    }
}
```

---

## 4. Utility Functions

### 4.1 Token Utility Matrix

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TOKEN UTILITY MATRIX                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  1. COMPUTE FEES                                                       │  │
│  │                                                                        │  │
│  │  All AI compute jobs require AETHEL payment:                          │  │
│  │  • Inference execution fees                                           │  │
│  │  • ZK proof generation fees                                           │  │
│  │  • Digital Seal creation fees                                         │  │
│  │  • Data storage fees (Vector Vault)                                   │  │
│  │                                                                        │  │
│  │  Demand Driver: Every enterprise AI verification pays in AETHEL      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  2. STAKING                                                            │  │
│  │                                                                        │  │
│  │  Validators must stake AETHEL to participate:                         │  │
│  │  • Minimum stake: 100,000 AETHEL                                      │  │
│  │  • Slashing for misbehavior                                           │  │
│  │  • Delegation allowed                                                 │  │
│  │                                                                        │  │
│  │  Lock-up Effect: Large portion of supply staked by validators        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  3. GOVERNANCE                                                         │  │
│  │                                                                        │  │
│  │  Token holders participate in protocol governance:                    │  │
│  │  • Protocol parameter changes                                         │  │
│  │  • Treasury allocation                                                │  │
│  │  • Validator set changes                                              │  │
│  │  • Upgrade proposals                                                  │  │
│  │                                                                        │  │
│  │  Voting Power: 1 AETHEL = 1 vote (quadratic for some proposals)      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  4. DATA RESIDENCY BONDS                                               │  │
│  │                                                                        │  │
│  │  For sensitive jurisdictional compute:                                │  │
│  │  • Validators post additional bonds for high-security jobs            │  │
│  │  • Higher bonds unlock access to restricted data                      │  │
│  │  • Slashing for jurisdiction violations                               │  │
│  │                                                                        │  │
│  │  Security Mechanism: Economic guarantee for data sovereignty          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  5. MODEL REGISTRY                                                     │  │
│  │                                                                        │  │
│  │  Model creators stake AETHEL to register models:                      │  │
│  │  • Registration bond (returned after review period)                   │  │
│  │  • Royalty payments for model usage                                   │  │
│  │  • Reputation-based access tiers                                      │  │
│  │                                                                        │  │
│  │  Creator Economy: Incentivizes high-quality model contributions      │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Utility Implementation

```rust
/// Token utility module
pub struct TokenUtility {
    /// Fee collection
    fee_module: FeeModule,

    /// Staking management
    staking_module: StakingModule,

    /// Governance
    governance_module: GovernanceModule,

    /// Model registry
    registry_module: RegistryModule,
}

impl TokenUtility {
    /// Calculate compute job fee
    pub fn calculate_job_fee(
        &self,
        job: &ComputeJob,
        network_state: &NetworkState,
    ) -> Fee {
        // Base fee (adjusted by EIP-1559-style mechanism)
        let base_fee = network_state.base_fee;

        // Compute units for this job
        let compute_units = self.estimate_compute_units(job);

        // Hardware premium (H100 costs more than generic)
        let hardware_multiplier = match job.hardware_requirement {
            HardwareType::Generic => Decimal::one(),
            HardwareType::Sgx => Decimal::from_str("1.2").unwrap(),
            HardwareType::NitroEnclave => Decimal::from_str("1.5").unwrap(),
            HardwareType::H100Confidential => Decimal::from_str("2.0").unwrap(),
        };

        // Jurisdiction premium (some regions have limited capacity)
        let jurisdiction_multiplier = self.jurisdiction_premium(&job.jurisdiction);

        // Priority fee (user-specified)
        let priority_fee = job.max_priority_fee_per_unit;

        // Total fee
        let fee_per_unit = base_fee * hardware_multiplier * jurisdiction_multiplier
            + priority_fee;

        Fee {
            amount: fee_per_unit * Decimal::from(compute_units),
            breakdown: FeeBreakdown {
                base: base_fee * Decimal::from(compute_units),
                hardware_premium: (hardware_multiplier - Decimal::one())
                    * base_fee * Decimal::from(compute_units),
                jurisdiction_premium: (jurisdiction_multiplier - Decimal::one())
                    * base_fee * Decimal::from(compute_units),
                priority: priority_fee * Decimal::from(compute_units),
            },
        }
    }

    /// Estimate compute units for a job
    fn estimate_compute_units(&self, job: &ComputeJob) -> u64 {
        // Based on model complexity and input size
        let model_flops = self.registry_module.get_model_flops(&job.model_id);
        let input_size = job.encrypted_input.len() as u64;

        // 1 compute unit = 1 billion FLOPs
        let base_units = model_flops / 1_000_000_000;

        // Additional units for large inputs
        let input_units = input_size / 1024; // 1 unit per KB

        base_units + input_units
    }

    /// Get jurisdiction fee multiplier
    fn jurisdiction_premium(&self, jurisdiction: &Jurisdiction) -> Decimal {
        match jurisdiction {
            Jurisdiction::Global => Decimal::one(),
            Jurisdiction::Uae => Decimal::from_str("1.3").unwrap(), // Limited UAE validators
            Jurisdiction::Eu => Decimal::from_str("1.1").unwrap(),
            Jurisdiction::Us => Decimal::from_str("1.1").unwrap(),
            Jurisdiction::SaudiArabia => Decimal::from_str("1.5").unwrap(), // Very limited
            Jurisdiction::China => Decimal::from_str("1.4").unwrap(),
            _ => Decimal::from_str("1.2").unwrap(),
        }
    }
}
```

---

## 5. Fee Mechanism

### 5.1 Fee Structure

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            FEE STRUCTURE                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FEE COMPONENTS (EIP-1559 Inspired)                                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  Total Fee = Base Fee + Priority Fee                                │    │
│  │                                                                      │    │
│  │  ┌───────────────────────────────────────────────────────────────┐  │    │
│  │  │  BASE FEE                                                      │  │    │
│  │  │                                                                 │  │    │
│  │  │  • Algorithmically adjusted based on block utilization         │  │    │
│  │  │  • Increases when blocks are > 50% full                        │  │    │
│  │  │  • Decreases when blocks are < 50% full                        │  │    │
│  │  │  • Max change: ±12.5% per block                                │  │    │
│  │  │  • 100% of base fee is BURNED                                  │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  │  ┌───────────────────────────────────────────────────────────────┐  │    │
│  │  │  PRIORITY FEE                                                  │  │    │
│  │  │                                                                 │  │    │
│  │  │  • User-specified tip to validators                            │  │    │
│  │  │  • Higher priority = faster inclusion                          │  │    │
│  │  │  • 100% goes to block producer                                 │  │    │
│  │  └───────────────────────────────────────────────────────────────┘  │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  CONGESTION-SQUARED BURN (Novel Mechanism)                                  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  In addition to EIP-1559, we apply a quadratic burn based on       │    │
│  │  network congestion:                                                │    │
│  │                                                                      │    │
│  │  Burn Rate = Base Fee × Congestion²                                 │    │
│  │                                                                      │    │
│  │  Where Congestion = (Block Utilization - 50%) / 50%                 │    │
│  │        Clamped to [0, 1]                                            │    │
│  │                                                                      │    │
│  │  Examples:                                                          │    │
│  │  • 50% utilization: Burn = Base × 0² = Base (normal)               │    │
│  │  • 75% utilization: Burn = Base × 0.5² = Base × 1.25               │    │
│  │  • 100% utilization: Burn = Base × 1² = Base × 2                   │    │
│  │                                                                      │    │
│  │  Effect: High demand creates EXPONENTIAL deflation                 │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Fee Implementation

```rust
/// Fee module implementing EIP-1559 + Congestion-Squared
pub struct FeeModule {
    /// Current base fee
    base_fee: Storage<Balance>,

    /// Target block gas (50% utilization)
    target_gas: u64,

    /// Maximum gas per block
    max_gas: u64,

    /// Fee history (for analysis)
    fee_history: RingBuffer<FeeRecord>,
}

impl FeeModule {
    /// Calculate next base fee based on previous block
    pub fn calculate_next_base_fee(
        &self,
        parent_gas_used: u64,
        parent_base_fee: Balance,
    ) -> Balance {
        // EIP-1559 style adjustment
        if parent_gas_used == self.target_gas {
            // Exactly at target - no change
            return parent_base_fee;
        }

        if parent_gas_used > self.target_gas {
            // Above target - increase fee
            let gas_delta = parent_gas_used - self.target_gas;
            let fee_delta = parent_base_fee * gas_delta as u128
                / self.target_gas as u128 / 8; // Max 12.5% increase
            parent_base_fee + fee_delta.max(1)
        } else {
            // Below target - decrease fee
            let gas_delta = self.target_gas - parent_gas_used;
            let fee_delta = parent_base_fee * gas_delta as u128
                / self.target_gas as u128 / 8; // Max 12.5% decrease
            parent_base_fee.saturating_sub(fee_delta).max(1)
        }
    }

    /// Calculate fee burn amount (including congestion-squared)
    pub fn calculate_burn(
        &self,
        transaction: &Transaction,
        block_utilization: f64,
    ) -> Balance {
        let base_fee = self.base_fee.get().unwrap_or(1);

        // Standard EIP-1559 burn
        let base_burn = base_fee * transaction.gas_used as u128;

        // Congestion-squared additional burn
        let congestion = ((block_utilization - 0.5) / 0.5).max(0.0).min(1.0);
        let congestion_multiplier = congestion * congestion;

        // Total burn = base_burn * (1 + congestion²)
        let total_burn = base_burn as f64 * (1.0 + congestion_multiplier);

        total_burn as Balance
    }

    /// Distribute fees after block finalization
    pub fn distribute_fees(
        &mut self,
        ctx: &mut Context,
        block: &Block,
    ) -> Result<FeeDistribution, FeeError> {
        let block_utilization = block.gas_used as f64 / self.max_gas as f64;

        let mut total_burned = 0u128;
        let mut total_to_validator = 0u128;

        for tx in &block.transactions {
            // Calculate burn (base fee + congestion penalty)
            let burn = self.calculate_burn(tx, block_utilization);
            total_burned += burn;

            // Priority fee goes to validator
            let priority = tx.priority_fee * tx.gas_used as u128;
            total_to_validator += priority;

            // Remaining goes to treasury (5%)
            let treasury_share = burn / 20; // 5%
            total_burned -= treasury_share;

            // Transfer to treasury
            ctx.token_module().transfer(
                &FEE_COLLECTOR,
                &TREASURY,
                treasury_share,
            )?;
        }

        // Burn tokens
        ctx.token_module().burn(&FEE_COLLECTOR, total_burned)?;

        // Pay validator
        ctx.token_module().transfer(
            &FEE_COLLECTOR,
            &block.proposer,
            total_to_validator,
        )?;

        Ok(FeeDistribution {
            burned: total_burned,
            to_validator: total_to_validator,
            to_treasury: total_burned / 19, // Approximate 5%
        })
    }
}
```

---

## 6. Staking Economics

### 6.1 Staking Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          STAKING ECONOMICS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  STAKING PARAMETERS                                                         │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Minimum Stake:        100,000 AETHEL                               │    │
│  │  Maximum Stake:        10,000,000 AETHEL (per validator)            │    │
│  │  Unbonding Period:     21 days                                      │    │
│  │  Reward Frequency:     Every block (~3 seconds)                     │    │
│  │  Commission Range:     0% - 20%                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  STAKING YIELD                                                              │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  APY = f(Staking Ratio, Inflation Rate, Fee Revenue)                │    │
│  │                                                                      │    │
│  │  Target Staking Ratio: 60%                                          │    │
│  │  At 60% staked: ~8% APY                                             │    │
│  │  At 30% staked: ~15% APY (incentivizes more staking)                │    │
│  │  At 80% staked: ~5% APY (discourages excessive staking)             │    │
│  │                                                                      │    │
│  │  APY │                                                               │    │
│  │  15% │         ○                                                     │    │
│  │      │           ╲                                                   │    │
│  │  10% │            ╲                                                  │    │
│  │      │             ╲                                                 │    │
│  │   8% │              ○ ← Target                                       │    │
│  │      │               ╲                                               │    │
│  │   5% │                ╲ ○                                            │    │
│  │      │                                                               │    │
│  │   0% └──────────────────────────────────────────────────────────    │    │
│  │       0%    30%    60%    80%   100%  Staking Ratio                 │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  DELEGATION                                                                 │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Token holders can delegate to validators                         │    │
│  │  • Delegators share in rewards (minus commission)                   │    │
│  │  • Delegators share in slashing (proportional)                      │    │
│  │  • No minimum delegation amount                                     │    │
│  │  • Instant re-delegation (no unbonding)                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Staking Implementation

```rust
/// Staking module
pub struct StakingModule {
    /// Validator set
    validators: ValidatorSet,

    /// Delegations
    delegations: DelegationMap,

    /// Unbonding queue
    unbonding_queue: UnbondingQueue,

    /// Staking parameters
    params: StakingParams,
}

#[derive(Clone, Debug)]
pub struct StakingParams {
    /// Minimum self-stake for validators
    pub min_self_stake: Balance,

    /// Maximum stake per validator (prevents centralization)
    pub max_stake_per_validator: Balance,

    /// Unbonding period (seconds)
    pub unbonding_period: u64,

    /// Target staking ratio (60%)
    pub target_staking_ratio: Decimal,

    /// Maximum commission rate
    pub max_commission: Decimal,

    /// Commission change rate limit (per day)
    pub commission_change_limit: Decimal,
}

impl StakingModule {
    /// Calculate validator APY based on staking ratio
    pub fn calculate_apy(&self, total_staked: Balance, total_supply: Balance) -> Decimal {
        let staking_ratio = Decimal::from_ratio(total_staked, total_supply);

        // Parameters for APY curve
        let target = self.params.target_staking_ratio; // 0.6
        let base_apy = Decimal::from_str("0.08").unwrap(); // 8%
        let min_apy = Decimal::from_str("0.05").unwrap(); // 5%
        let max_apy = Decimal::from_str("0.15").unwrap(); // 15%

        if staking_ratio < target {
            // Below target - higher APY to incentivize staking
            let ratio = staking_ratio / target;
            max_apy - (max_apy - base_apy) * ratio
        } else {
            // Above target - lower APY to discourage excessive staking
            let ratio = (staking_ratio - target) / (Decimal::one() - target);
            base_apy - (base_apy - min_apy) * ratio
        }
    }

    /// Delegate tokens to a validator
    pub fn delegate(
        &mut self,
        ctx: &mut Context,
        delegator: &Address,
        validator: &Address,
        amount: Balance,
    ) -> Result<(), StakingError> {
        // Verify validator exists
        if !self.validators.contains(validator) {
            return Err(StakingError::ValidatorNotFound);
        }

        // Check validator not over max stake
        let current_stake = self.get_validator_total_stake(validator);
        if current_stake + amount > self.params.max_stake_per_validator {
            return Err(StakingError::ValidatorOverMaxStake);
        }

        // Lock tokens
        ctx.token_module().lock(delegator, amount, LockType::Staking)?;

        // Record delegation
        let delegation = Delegation {
            delegator: *delegator,
            validator: *validator,
            amount,
            start_height: ctx.block_height(),
        };
        self.delegations.add(delegation);

        ctx.emit_event(DelegateEvent {
            delegator: *delegator,
            validator: *validator,
            amount,
        });

        Ok(())
    }

    /// Undelegate tokens (starts unbonding)
    pub fn undelegate(
        &mut self,
        ctx: &mut Context,
        delegator: &Address,
        validator: &Address,
        amount: Balance,
    ) -> Result<u64, StakingError> {
        // Find delegation
        let delegation = self.delegations.get(delegator, validator)
            .ok_or(StakingError::DelegationNotFound)?;

        if delegation.amount < amount {
            return Err(StakingError::InsufficientDelegation);
        }

        // Reduce delegation
        self.delegations.reduce(delegator, validator, amount)?;

        // Create unbonding entry
        let completion_time = ctx.block_time() + self.params.unbonding_period;
        let unbonding = UnbondingEntry {
            delegator: *delegator,
            validator: *validator,
            amount,
            completion_time,
        };
        self.unbonding_queue.push(unbonding);

        ctx.emit_event(UndelegateEvent {
            delegator: *delegator,
            validator: *validator,
            amount,
            completion_time,
        });

        Ok(completion_time)
    }

    /// Distribute rewards for a block
    pub fn distribute_rewards(
        &mut self,
        ctx: &mut Context,
        block_reward: Balance,
        fee_reward: Balance,
    ) -> Result<(), StakingError> {
        let total_reward = block_reward + fee_reward;

        // Distribute proportionally to stake
        let total_staked = self.total_staked();

        for validator in self.validators.iter() {
            let validator_stake = self.get_validator_total_stake(&validator.address);
            let stake_share = Decimal::from_ratio(validator_stake, total_staked);
            let validator_reward = total_reward * stake_share;

            // Commission to validator operator
            let commission = validator_reward * validator.commission;
            ctx.token_module().mint(&validator.address, commission.to_u128())?;

            // Remainder to delegators
            let delegator_pool = validator_reward - commission;
            self.distribute_to_delegators(ctx, &validator.address, delegator_pool)?;
        }

        Ok(())
    }
}
```

---

## 7. Emission and Deflation

### 7.1 Capped Emission Framework

- Maximum supply is fixed at **10,000,000,000 AETHEL**
- No tail emissions and no uncapped inflation schedule
- New issuance comes only from pre-allocated pools (primarily Compute / PoUW rewards with decay)

| Emission Source | Allocation | Release Model |
|-----------------|------------|---------------|
| Compute / PoUW Rewards | 3,000,000,000 | 15-year algorithmic decay, contribution-gated |
| Core Contributors | 2,000,000,000 | 6m cliff + 42m linear |
| Strategic/Seed | 550,000,000 | 12m cliff + 24m linear |
| Public Sales | 750,000,000 | 20% TGE + 80% over 18 months |
| Airdrop (Seals) | 700,000,000 | 25% TGE + 75% over 12 months |
| Treasury & MM | 600,000,000 | 25% TGE + 75% over 36 months |
| Ecosystem & Grants | 1,500,000,000 | 2% TGE + 48m linear (54m total) |
| Insurance Fund | 500,000,000 | 10% TGE + 30m linear |
| Contingency Reserve | 400,000,000 | 12m cliff, TBD vesting |

### 7.2 Deflation Mechanics

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DEFLATION MECHANICS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  BURN SOURCES                                                               │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  1. Base Fee Burn (EIP-1559 Style)                                    │  │
│  │     • 100% of base fees burned                                        │  │
│  │     • Estimated: 1-3% of supply annually at high utilization         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  2. Congestion-Squared Burn                                           │  │
│  │     • Additional burn during high congestion                          │  │
│  │     • Can double the burn rate at 100% utilization                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  3. Slashing Burns                                                    │  │
│  │     • Slashed stake is burned (not redistributed)                    │  │
│  │     • Disincentivizes attacks, permanent supply reduction            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  4. Failed Transaction Burns                                          │  │
│  │     • Out-of-gas transactions still pay base fee                     │  │
│  │     • Prevents spam attacks                                          │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  NET SUPPLY SCENARIOS (WITH CAPPED SUPPLY)                                  │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  Scenario        │ Emissions │ Burn Rate │ Net Change │ Result     │    │
│  │  ─────────────────────────────────────────────────────────────────  │    │
│  │  Early Network   │  Higher   │   0.5%    │  Positive  │ Expansion  │    │
│  │  Growth Phase    │  Moderate │   2.0%    │  Neutral   │ Stable     │    │
│  │  Mature Demand   │  Lower    │   4.0%    │  Negative  │ Deflationary│   │
│  │  High Utilization│  Lower    │   6.0%+   │  Negative  │ Strong burn│    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  BREAKEVEN ANALYSIS                                                         │
│                                                                              │
│  Network becomes net deflationary when burn exceeds released emissions:     │
│  • Average block utilization is sustained at enterprise demand levels       │
│  • Fee burn + slashing burn > unlocked emissions                            │
│  • This is achievable in mature utilization phases                          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.3 Supply Projection

```rust
/// Token supply projections
pub struct SupplyProjection {
    /// Starting supply
    initial_supply: Balance,

    /// Maximum supply hard cap
    max_supply: Balance,

    /// Scheduled pool emission model
    emission_schedule: EmissionSchedule,

    /// Burn model
    burn_model: BurnModel,
}

impl SupplyProjection {
    /// Project supply at future time
    pub fn project(&self, years: u64, utilization_rate: f64) -> ProjectedSupply {
        let mut supply = self.initial_supply;
        let mut total_emitted = 0u128;
        let mut total_burned = 0u128;

        for year in 0..years {
            // Scheduled emission for this year (bounded by cap)
            let emitted = self.emission_schedule.emission_for_year(year);
            let remaining_to_cap = self.max_supply.saturating_sub(supply);
            let emitted_capped = emitted.min(remaining_to_cap);
            total_emitted += emitted_capped;

            // Burn based on utilization
            let burn_rate = self.burn_model.annual_rate(utilization_rate);
            let burned = (supply as f64 * burn_rate) as u128;
            total_burned += burned;

            // Net supply change
            supply = supply + emitted_capped - burned;
        }

        ProjectedSupply {
            final_supply: supply,
            total_emitted,
            total_burned,
            net_change: (total_emitted as i128 - total_burned as i128),
            net_percentage: ((supply as f64 / self.initial_supply as f64) - 1.0) * 100.0,
        }
    }
}

/// Example projections (at 10B hard-capped supply):
///
/// 5 Years, 50% utilization:
///   - Emitted: from scheduled pools
///   - Burned: 80M AETHEL
///   - Net: emission-dependent
///   - Final: <= 10B AETHEL
///
/// 5 Years, 80% utilization:
///   - Emitted: from scheduled pools
///   - Burned: 180M AETHEL
///   - Net: potentially deflationary
///   - Final: <= 10B AETHEL
///
/// 10 Years, 70% utilization:
///   - Emissions decay materially
///   - Burns may exceed unlocked emissions
///   - Final supply remains below hard cap
```

---

## 8. Governance Token

### 8.1 Governance Rights

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          GOVERNANCE RIGHTS                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  BI-CAMERAL GOVERNANCE SYSTEM                                               │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │                    ┌───────────────────────┐                          │  │
│  │                    │    GOVERNANCE         │                          │  │
│  │                    │    PROPOSAL           │                          │  │
│  │                    └───────────┬───────────┘                          │  │
│  │                                │                                       │  │
│  │              ┌─────────────────┴─────────────────┐                    │  │
│  │              │                                   │                    │  │
│  │              ▼                                   ▼                    │  │
│  │   ┌─────────────────────┐           ┌─────────────────────┐          │  │
│  │   │  HOUSE OF TOKENS    │           │ HOUSE OF SOVEREIGNS │          │  │
│  │   │                     │           │                     │          │  │
│  │   │  • 1 AETHEL = 1 vote│           │  • 1 validator = 1  │          │  │
│  │   │  • Token-weighted   │           │    vote             │          │  │
│  │   │  • Any holder can   │           │  • Must be active   │          │  │
│  │   │    vote             │           │    validator        │          │  │
│  │   │  • Delegatable      │           │  • KYC required     │          │  │
│  │   │                     │           │                     │          │  │
│  │   └──────────┬──────────┘           └──────────┬──────────┘          │  │
│  │              │                                   │                    │  │
│  │              └─────────────────┬─────────────────┘                    │  │
│  │                                │                                       │  │
│  │                                ▼                                       │  │
│  │              ┌─────────────────────────────────┐                      │  │
│  │              │   BOTH HOUSES MUST APPROVE      │                      │  │
│  │              │   (prevents mob rule AND        │                      │  │
│  │              │    prevents enterprise capture) │                      │  │
│  │              └─────────────────────────────────┘                      │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  PROPOSAL TYPES                                                             │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Type           │ Token House │ Sovereign House │ Quorum    │ Pass │    │
│  │  ─────────────────────────────────────────────────────────────────  │    │
│  │  Parameter      │ Required    │ Required        │ 20%       │ 50%  │    │
│  │  Treasury       │ Required    │ Required        │ 30%       │ 66%  │    │
│  │  Validator Set  │ Not Required│ Required        │ N/A       │ 66%  │    │
│  │  Protocol       │ Required    │ Required        │ 40%       │ 75%  │    │
│  │  Emergency      │ Not Required│ Required        │ N/A       │ 80%  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Governance Implementation

```rust
/// Governance module
pub struct GovernanceModule {
    /// Active proposals
    proposals: ProposalStore,

    /// Votes
    votes: VoteStore,

    /// Parameters
    params: GovernanceParams,
}

#[derive(Clone, Debug)]
pub struct Proposal {
    /// Unique proposal ID
    pub id: u64,

    /// Proposer address
    pub proposer: Address,

    /// Proposal type
    pub proposal_type: ProposalType,

    /// Title
    pub title: String,

    /// Description
    pub description: String,

    /// Executable messages (if passed)
    pub messages: Vec<GovMsg>,

    /// Deposit (returned if quorum reached)
    pub deposit: Balance,

    /// Voting period end
    pub voting_end: u64,

    /// Status
    pub status: ProposalStatus,
}

#[derive(Clone, Debug)]
pub enum ProposalType {
    /// Protocol parameter change
    ParameterChange {
        changes: Vec<ParamChange>,
    },

    /// Treasury spending
    TreasurySpend {
        recipient: Address,
        amount: Balance,
        purpose: String,
    },

    /// Validator set update
    ValidatorUpdate {
        additions: Vec<ValidatorInfo>,
        removals: Vec<Address>,
    },

    /// Protocol upgrade
    ProtocolUpgrade {
        name: String,
        height: u64,
        plan: UpgradePlan,
    },

    /// Emergency action
    Emergency {
        action: EmergencyAction,
        justification: String,
    },
}

impl GovernanceModule {
    /// Submit a proposal
    pub fn submit_proposal(
        &mut self,
        ctx: &mut Context,
        proposer: &Address,
        proposal: Proposal,
        deposit: Balance,
    ) -> Result<u64, GovernanceError> {
        // Check minimum deposit
        let min_deposit = self.params.min_deposit_for(&proposal.proposal_type);
        if deposit < min_deposit {
            return Err(GovernanceError::InsufficientDeposit);
        }

        // Lock deposit
        ctx.token_module().lock(proposer, deposit, LockType::Governance)?;

        // Store proposal
        let id = self.proposals.next_id();
        let mut proposal = proposal;
        proposal.id = id;
        proposal.deposit = deposit;
        proposal.voting_end = ctx.block_time() + self.params.voting_period;
        proposal.status = ProposalStatus::Voting;

        self.proposals.store(proposal.clone());

        ctx.emit_event(ProposalSubmittedEvent {
            id,
            proposer: *proposer,
            proposal_type: proposal.proposal_type,
        });

        Ok(id)
    }

    /// Cast vote from token holder
    pub fn vote_token_house(
        &mut self,
        ctx: &mut Context,
        voter: &Address,
        proposal_id: u64,
        option: VoteOption,
    ) -> Result<(), GovernanceError> {
        let proposal = self.proposals.get(proposal_id)?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::ProposalNotVoting);
        }

        if ctx.block_time() > proposal.voting_end {
            return Err(GovernanceError::VotingEnded);
        }

        // Get voting power (token balance)
        let voting_power = ctx.token_module().balance(voter);

        // Record vote
        let vote = Vote {
            proposal_id,
            voter: *voter,
            house: House::Tokens,
            option,
            power: voting_power,
        };
        self.votes.record(vote);

        Ok(())
    }

    /// Cast vote from validator (Sovereign House)
    pub fn vote_sovereign_house(
        &mut self,
        ctx: &mut Context,
        validator: &Address,
        proposal_id: u64,
        option: VoteOption,
    ) -> Result<(), GovernanceError> {
        // Verify caller is active validator
        if !ctx.staking_module().is_active_validator(validator) {
            return Err(GovernanceError::NotValidator);
        }

        let proposal = self.proposals.get(proposal_id)?;

        if proposal.status != ProposalStatus::Voting {
            return Err(GovernanceError::ProposalNotVoting);
        }

        // Sovereign house: 1 validator = 1 vote
        let vote = Vote {
            proposal_id,
            voter: *validator,
            house: House::Sovereigns,
            option,
            power: 1,
        };
        self.votes.record(vote);

        Ok(())
    }

    /// Tally votes and execute if passed
    pub fn tally_proposal(
        &mut self,
        ctx: &mut Context,
        proposal_id: u64,
    ) -> Result<ProposalResult, GovernanceError> {
        let mut proposal = self.proposals.get(proposal_id)?;

        if ctx.block_time() <= proposal.voting_end {
            return Err(GovernanceError::VotingNotEnded);
        }

        let votes = self.votes.for_proposal(proposal_id);

        // Tally Token House
        let token_result = self.tally_house(&votes, House::Tokens, &proposal)?;

        // Tally Sovereign House
        let sovereign_result = self.tally_house(&votes, House::Sovereigns, &proposal)?;

        // Check both houses (bi-cameral)
        let passed = token_result.passed && sovereign_result.passed;

        if passed {
            proposal.status = ProposalStatus::Passed;
            self.execute_proposal(ctx, &proposal)?;
        } else {
            proposal.status = ProposalStatus::Rejected;
        }

        // Return deposit if quorum reached
        if token_result.quorum_reached {
            ctx.token_module().unlock(&proposal.proposer, proposal.deposit)?;
        } else {
            // Burn deposit if quorum not reached
            ctx.token_module().burn(&proposal.proposer, proposal.deposit)?;
        }

        self.proposals.update(proposal.clone());

        Ok(ProposalResult {
            passed,
            token_house: token_result,
            sovereign_house: sovereign_result,
        })
    }
}
```

---

## 9. Economic Security

### 9.1 Attack Cost Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ECONOMIC SECURITY ANALYSIS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ATTACK VECTORS AND COSTS                                                   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  1. 33% ATTACK (Halt Network)                                         │  │
│  │                                                                        │  │
│  │  Requirements:                                                         │  │
│  │  • Control 1/3 of staked tokens                                       │  │
│  │  • At 60% staked: 2.0B AETHEL (20% of supply)                         │  │
│  │  • At $10/token: $20,000,000,000 (20 billion USD)                     │  │
│  │                                                                        │  │
│  │  Result: Network halts (no blocks produced)                           │  │
│  │  Attacker Cost: Stake value crashes, losing most investment           │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  2. 66% ATTACK (Control Network)                                      │  │
│  │                                                                        │  │
│  │  Requirements:                                                         │  │
│  │  • Control 2/3 of staked tokens                                       │  │
│  │  • At 60% staked: 4.0B AETHEL (40% of supply)                         │  │
│  │  • At $10/token: $40,000,000,000 (40 billion USD)                     │  │
│  │                                                                        │  │
│  │  Result: Can censor transactions, produce invalid blocks              │  │
│  │  Detection: Obvious to network, leads to social fork                  │  │
│  │  Attacker Cost: Total stake slashed (100%)                            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  3. LONG-RANGE ATTACK                                                  │  │
│  │                                                                        │  │
│  │  Requirements:                                                         │  │
│  │  • Obtain old validator keys (after unbonding)                        │  │
│  │  • Create alternative history from old state                          │  │
│  │                                                                        │  │
│  │  Mitigation:                                                          │  │
│  │  • Weak subjectivity checkpoints (embedded in clients)                │  │
│  │  • Social consensus on canonical chain                                │  │
│  │  • 21-day unbonding period (sufficient for checkpoint)                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  4. NOTHING-AT-STAKE                                                   │  │
│  │                                                                        │  │
│  │  Concern: Validators sign multiple conflicting blocks                 │  │
│  │                                                                        │  │
│  │  Mitigation:                                                          │  │
│  │  • Slashing for equivocation (double-signing)                         │  │
│  │  • 100% stake slashed + tombstoning                                   │  │
│  │  • CometBFT finality (no forks possible)                              │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  SECURITY BUDGET SUMMARY                                                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  At Steady State (Year 3+):                                         │    │
│  │                                                                      │    │
│  │  Total Supply (Cap):  10B AETHEL                                    │    │
│  │  Staked:              60% = 6B AETHEL                               │    │
│  │  Token Price:         $10 (assumption)                              │    │
│  │  Staked Value:        $60B                                          │    │
│  │                                                                      │    │
│  │  Security Budget:     Scheduled emissions + fee revenue             │    │
│  │                       (no uncapped inflation tail)                  │    │
│  │                                                                      │    │
│  │  Attack Cost (66%):   $40B + hardware + opportunity cost            │    │
│  │  Attack Profit:       Near zero (stake slashed, price crashes)      │    │
│  │  Net Attack ROI:      Massively negative                            │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 10. Long-Term Sustainability

### 10.1 Sustainability Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      LONG-TERM SUSTAINABILITY                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  REVENUE SOURCES                                                            │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  1. Compute Fees (Primary)                                            │  │
│  │     • Enterprise AI verification services                             │  │
│  │     • Pay-per-inference model                                         │  │
│  │     • Scales with adoption                                            │  │
│  │                                                                        │  │
│  │  2. Data Storage Fees                                                 │  │
│  │     • Vector Vault for LLM embeddings                                 │  │
│  │     • Model weight storage                                            │  │
│  │     • Recurring revenue stream                                        │  │
│  │                                                                        │  │
│  │  3. Bridge Fees                                                       │  │
│  │     • Cross-chain proof delivery                                      │  │
│  │     • Polygon, IBC, Ethereum bridges                                  │  │
│  │                                                                        │  │
│  │  4. Premium Features                                                  │  │
│  │     • Priority execution                                              │  │
│  │     • Custom hardware allocation                                      │  │
│  │     • SLA guarantees                                                  │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  EXPENSE STRUCTURE                                                          │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  Fixed Costs:                                                         │  │
│  │  • Validator infrastructure (~$5M/year for 100 validators)            │  │
│  │  • Core development team                                              │  │
│  │  • Security audits                                                    │  │
│  │                                                                        │  │
│  │  Variable Costs:                                                      │  │
│  │  • Block rewards (scheduled PoUW emissions)                           │  │
│  │  • Ecosystem grants                                                   │  │
│  │  • Marketing and BD                                                   │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  BREAK-EVEN ANALYSIS                                                        │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                                                                      │    │
│  │  Year 1-2: Subsidized by treasury                                   │    │
│  │  Year 3:   Fee revenue covers 50% of costs                          │    │
│  │  Year 4:   Fee revenue covers 100% of costs                         │    │
│  │  Year 5+:  Fee revenue can exceed unlocked emissions                │    │
│  │            (net deflationary in high-utilization periods)           │    │
│  │                                                                      │    │
│  │  Breakeven Requirement:                                              │    │
│  │  • ~1,000 active enterprise users                                   │    │
│  │  • ~$100M annual compute job volume                                 │    │
│  │  • Achievable with GCC financial sector adoption                    │    │
│  │                                                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  COMPETITIVE MOAT                                                           │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                                                                        │  │
│  │  1. Network Effects                                                   │  │
│  │     • More validators → Better coverage → More enterprises           │  │
│  │     • More enterprises → Higher fees → More validators               │  │
│  │                                                                        │  │
│  │  2. Hardware Moat                                                     │  │
│  │     • TEE hardware is expensive ($500K+/validator)                   │  │
│  │     • First-mover advantage in hardware partnerships                 │  │
│  │     • Attestation infrastructure is hard to replicate                │  │
│  │                                                                        │  │
│  │  3. Regulatory Relationships                                          │  │
│  │     • Early compliance certifications                                │  │
│  │     • Trusted by UAE/GCC regulators                                  │  │
│  │     • Compliance reputation compounds                                │  │
│  │                                                                        │  │
│  │  4. Data Gravity                                                      │  │
│  │     • Enterprises store verified model results                       │  │
│  │     • Switching costs increase over time                             │  │
│  │     • Audit trail is permanent and valuable                          │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. Technical Integration Priorities

Reference TRD: `docs/protocol/institutional-stablecoin-integration-trd-v2.md`

### 11.1 Priority Workstreams

1. Build stablecoin bridges for **USDC, USDT, USDU, and DDSC**.
2. Implement reserve and verification modules for all supported stablecoins:
   - Verify backing status
   - Validate on-chain reserve proofs (when available)
   - Track third-party audit status and freshness
3. Define risk parameters per stablecoin:
   - Mint ceilings
   - Daily transaction limits
   - Circuit breakers
   - Apply stricter defaults for higher-risk or newer assets, especially **USDU** and **DDSC**

### 11.2 Stablecoin Risk Control Matrix (Required)

| Stablecoin | Mint Ceiling | Daily Tx Limit | Circuit Breakers | Reserve/Proof Verification | Audit Monitoring |
|------------|--------------|----------------|------------------|----------------------------|------------------|
| USDC | Required | Required | Required | Required | Required |
| USDT | Required | Required | Required | Required | Required |
| USDU | Required (conservative) | Required (conservative) | Required (sensitive thresholds) | Required | Required (high cadence) |
| DDSC | Required (conservative) | Required (conservative) | Required (sensitive thresholds) | Required | Required (high cadence) |

### 11.3 DDSC Integration Context

**DDSC (Dirham Digital Stablecoin)** is documented as a UAE Central Bank-approved, 1:1 Dirham-backed stablecoin launched in **February 2026** by **IHC**, **Sirius International Holding**, and **First Abu Dhabi Bank (FAB)**. It operates on the **ADI Chain** (a sovereign, compliance-ready Layer-2 blockchain) and targets institutional payments and trade finance use cases.

Given this profile, DDSC integration should include:

- Bridge and settlement path support with ADI Chain interoperability
- Full reserve and verification coverage before enabling broader mint/flow limits
- Conservative initial risk limits with staged expansion based on observed stability

---

## Appendix A: Token Comparison

| Metric | Bitcoin | Ethereum | Aethelred |
|--------|---------|----------|-----------|
| Consensus | PoW | PoS | PoUW |
| Supply Cap | 21M | Uncapped | 10B hard cap |
| Inflation | Halving | ~0.5%/year | No tail inflation (scheduled capped emissions) |
| Fee Model | Auction | EIP-1559 | EIP-1559 + Congestion² |
| Staking Yield | N/A | 3-5% | 5-15% |
| Utility | Store of Value | Gas + DeFi | Compute + Governance |

---

## Appendix B: Key Addresses

| Address | Purpose |
|---------|---------|
| `aethelred1treasury...` | Treasury (governance-controlled) |
| `aethelred1ecosystem...` | Ecosystem fund |
| `aethelred1validator...` | Validator incentive pool |
| `aethelred1burn...` | Burn address (unspendable) |

---

<p align="center">
  <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
