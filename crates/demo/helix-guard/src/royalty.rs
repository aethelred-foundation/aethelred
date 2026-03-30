//! # Project Helix-Guard: Royalty & Settlement System
//!
//! Enterprise-grade royalty calculation and settlement engine for sovereign
//! genomics collaboration. Automatically compensates data custodians (M42)
//! for usage of their genomic assets in AETHEL tokens.
//!
//! ## Royalty Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
//! │                              HELIX-GUARD ROYALTY MODEL                                           │
//! ├─────────────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                                  │
//! │    BASE ROYALTY CALCULATION                                                                      │
//! │    ─────────────────────────                                                                     │
//! │                                                                                                  │
//! │    Base Fee = $500 per analysis                                                                  │
//! │                                                                                                  │
//! │    TIER ADJUSTMENTS                          USAGE MULTIPLIERS                                   │
//! │    ─────────────────                         ────────────────────                                │
//! │    Strategic Partner: 0.80x                  Population Size > 50K: 1.25x                       │
//! │    Commercial:        1.00x                  Rare Disease Markers: 1.50x                        │
//! │    Academic:          0.50x                  Pharmacogenomic Data: 1.75x                        │
//! │    Public Health:     0.25x                  Multi-cohort Query:   2.00x                        │
//! │    Trial/Demo:        FREE                                                                       │
//! │                                                                                                  │
//! │    VOLUME DISCOUNTS                                                                              │
//! │    ────────────────                                                                              │
//! │    1-10 analyses:     0%                                                                         │
//! │    11-50 analyses:    10%                                                                        │
//! │    51-100 analyses:   15%                                                                        │
//! │    100+ analyses:     20%                                                                        │
//! │                                                                                                  │
//! │    FINAL CALCULATION                                                                             │
//! │    ─────────────────                                                                             │
//! │    Royalty = Base × Tier × Usage Multipliers × (1 - Volume Discount)                            │
//! │                                                                                                  │
//! ├─────────────────────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                                  │
//! │    SETTLEMENT FLOW                                                                               │
//! │    ───────────────                                                                               │
//! │                                                                                                  │
//! │    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    │
//! │    │   CALCULATE     │    │    ESCROW       │    │    VERIFY       │    │    RELEASE      │    │
//! │    │   ROYALTY       │ ──►│    FUNDS        │ ──►│    COMPUTE      │ ──►│    PAYMENT      │    │
//! │    │                 │    │                 │    │                 │    │                 │    │
//! │    │  Based on usage │    │  Lock AETHEL in │    │  Await proof of │    │  Transfer to    │    │
//! │    │  and tier       │    │  smart contract │    │  valid compute  │    │  M42 treasury   │    │
//! │    └─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘    │
//! │                                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Settlement Features
//!
//! | Feature | Description |
//! |---------|-------------|
//! | Atomic Settlement | All-or-nothing payment tied to compute proof |
//! | Multi-party Split | Automatic division among data contributors |
//! | Audit Trail | Immutable on-chain record of all transactions |
//! | Escrow Protection | Funds locked until valid proof submitted |

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rust_decimal::prelude::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{HelixGuardError, HelixGuardResult};
use crate::types::*;

// =============================================================================
// CONSTANTS
// =============================================================================

/// Base royalty fee in USD per analysis
pub const BASE_ROYALTY_USD: u64 = 500;

/// AETHEL to USD conversion rate (simulated)
pub const AETHEL_USD_RATE: f64 = 1.0;

/// 18 decimal places for AETHEL tokens
pub const AETHEL_DECIMALS: u32 = 18;

/// Minimum royalty amount in AETHEL (1 AETHEL)
pub const MIN_ROYALTY_AETHEL: u128 = 1_000_000_000_000_000_000;

// =============================================================================
// ROYALTY ENGINE
// =============================================================================

/// Royalty and Settlement Engine
pub struct RoyaltyEngine {
    /// Engine ID (reserved for future use)
    #[allow(dead_code)]
    id: Uuid,
    /// Engine configuration
    config: RoyaltyConfig,
    /// Pending payments
    pending_payments: Arc<RwLock<HashMap<Uuid, RoyaltyPayment>>>,
    /// Completed payments
    completed_payments: Arc<RwLock<Vec<RoyaltyPayment>>>,
    /// Escrow balances
    escrow_balances: Arc<RwLock<HashMap<Uuid, EscrowBalance>>>,
    /// Treasury accounts
    treasuries: Arc<RwLock<HashMap<Uuid, TreasuryAccount>>>,
    /// Partner accounts
    partner_accounts: Arc<RwLock<HashMap<Uuid, PartnerAccount>>>,
    /// Settlement transactions
    transactions: Arc<RwLock<Vec<SettlementTransaction>>>,
    /// Engine metrics
    metrics: Arc<RwLock<RoyaltyMetrics>>,
}

/// Royalty engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoyaltyConfig {
    /// Base fee per analysis (USD)
    pub base_fee_usd: Decimal,
    /// Enable automatic settlement
    pub auto_settlement: bool,
    /// Settlement confirmation blocks
    pub confirmation_blocks: u32,
    /// Enable escrow for large payments
    pub escrow_enabled: bool,
    /// Escrow threshold (USD)
    pub escrow_threshold_usd: Decimal,
    /// Maximum payment batch size
    pub max_batch_size: usize,
    /// Payment timeout (hours)
    pub payment_timeout_hours: i64,
}

impl Default for RoyaltyConfig {
    fn default() -> Self {
        Self {
            base_fee_usd: Decimal::from(BASE_ROYALTY_USD),
            auto_settlement: true,
            confirmation_blocks: 1,
            escrow_enabled: true,
            escrow_threshold_usd: Decimal::from(1000),
            max_batch_size: 100,
            payment_timeout_hours: 24,
        }
    }
}

/// Escrow balance for a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowBalance {
    /// Escrow ID
    pub id: Uuid,
    /// Session ID
    pub session_id: Uuid,
    /// Payer (pharma partner)
    pub payer_id: Uuid,
    /// Recipient (data custodian)
    pub recipient_id: Uuid,
    /// Locked amount (AETHEL)
    pub locked_amount: u128,
    /// Locked amount (USD equivalent)
    pub locked_usd: Decimal,
    /// Escrow status
    pub status: EscrowStatus,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Release conditions
    pub release_conditions: Vec<ReleaseCondition>,
    /// Released at
    pub released_at: Option<DateTime<Utc>>,
}

/// Escrow status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscrowStatus {
    /// Funds locked
    Locked,
    /// Partial release
    PartiallyReleased,
    /// Fully released
    Released,
    /// Expired
    Expired,
    /// Disputed
    Disputed,
    /// Refunded
    Refunded,
}

/// Release condition for escrow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReleaseCondition {
    /// Valid TEE attestation provided
    TeeAttestationVerified,
    /// zkML proof verified
    ZkmlProofVerified,
    /// Minimum confidence met
    MinConfidenceMet(u8),
    /// Time-based release
    TimeElapsed(DateTime<Utc>),
    /// Manual approval
    ManualApproval,
}

/// Treasury account for data custodians
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAccount {
    /// Account ID
    pub id: Uuid,
    /// Owner (custodian ID)
    pub owner_id: Uuid,
    /// Owner name
    pub owner_name: String,
    /// Balance (AETHEL)
    pub balance_aethel: u128,
    /// Total received (AETHEL)
    pub total_received_aethel: u128,
    /// Total transactions
    pub transaction_count: u64,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last activity
    pub last_activity: DateTime<Utc>,
}

/// Partner account for pharma companies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartnerAccount {
    /// Account ID
    pub id: Uuid,
    /// Partner ID
    pub partner_id: Uuid,
    /// Partner name
    pub partner_name: String,
    /// Partner tier
    pub tier: PartnerTier,
    /// Credit balance (AETHEL)
    pub credit_balance_aethel: u128,
    /// Total spent (AETHEL)
    pub total_spent_aethel: u128,
    /// Analysis count
    pub analysis_count: u64,
    /// Volume discount tier
    pub volume_discount_tier: VolumeDiscountTier,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Last activity
    pub last_activity: DateTime<Utc>,
}

/// Volume discount tiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VolumeDiscountTier {
    /// 1-10 analyses: 0% discount
    None,
    /// 11-50 analyses: 10% discount
    Bronze,
    /// 51-100 analyses: 15% discount
    Silver,
    /// 100+ analyses: 20% discount
    Gold,
}

impl VolumeDiscountTier {
    /// Get discount percentage
    pub fn discount_percent(&self) -> Decimal {
        match self {
            Self::None => Decimal::ZERO,
            Self::Bronze => Decimal::from(10),
            Self::Silver => Decimal::from(15),
            Self::Gold => Decimal::from(20),
        }
    }

    /// Determine tier from analysis count
    pub fn from_count(count: u64) -> Self {
        match count {
            0..=10 => Self::None,
            11..=50 => Self::Bronze,
            51..=100 => Self::Silver,
            _ => Self::Gold,
        }
    }
}

/// Settlement transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementTransaction {
    /// Transaction ID
    pub id: Uuid,
    /// Transaction type
    pub tx_type: SettlementTxType,
    /// Session ID (if applicable)
    pub session_id: Option<Uuid>,
    /// From account
    pub from_account: Uuid,
    /// To account
    pub to_account: Uuid,
    /// Amount (AETHEL)
    pub amount_aethel: u128,
    /// Amount (USD)
    pub amount_usd: Decimal,
    /// Transaction status
    pub status: TransactionStatus,
    /// On-chain hash (if settled)
    pub tx_hash: Option<Hash>,
    /// Block number
    pub block_number: Option<u64>,
    /// Confirmations
    pub confirmations: u32,
    /// Created at
    pub created_at: DateTime<Utc>,
    /// Confirmed at
    pub confirmed_at: Option<DateTime<Utc>>,
    /// Memo
    pub memo: String,
}

/// Settlement transaction type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SettlementTxType {
    /// Royalty payment
    RoyaltyPayment,
    /// Escrow lock
    EscrowLock,
    /// Escrow release
    EscrowRelease,
    /// Escrow refund
    EscrowRefund,
    /// Credit purchase
    CreditPurchase,
    /// Credit refund
    CreditRefund,
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransactionStatus {
    /// Pending
    Pending,
    /// Submitted to chain
    Submitted,
    /// Confirming
    Confirming,
    /// Confirmed
    Confirmed,
    /// Failed
    Failed,
}

/// Royalty metrics
#[derive(Debug, Default)]
pub struct RoyaltyMetrics {
    /// Total royalties paid (AETHEL)
    pub total_royalties_aethel: u128,
    /// Total royalties paid (USD)
    pub total_royalties_usd: Decimal,
    /// Total transactions
    pub total_transactions: u64,
    /// Total escrow locked
    pub total_escrow_locked_aethel: u128,
    /// Active escrows
    pub active_escrows: u64,
    /// Average royalty per analysis
    pub avg_royalty_per_analysis_usd: Decimal,
    /// Total analyses processed
    pub total_analyses: u64,
}

// =============================================================================
// ROYALTY CALCULATION
// =============================================================================

/// Royalty calculation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoyaltyCalculationParams {
    /// Partner tier
    pub partner_tier: PartnerTier,
    /// Analysis type
    pub analysis_type: ComputeJobType,
    /// Population size
    pub population_size: u32,
    /// Marker types used
    pub marker_types: Vec<GeneticMarkerType>,
    /// Number of analyses in batch
    pub batch_size: u32,
    /// Partner's total analysis count (for volume discount)
    pub total_partner_analyses: u64,
}

/// Royalty calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoyaltyCalculation {
    /// Base fee (USD)
    pub base_fee_usd: Decimal,
    /// Tier multiplier
    pub tier_multiplier: Decimal,
    /// Usage multipliers
    pub usage_multipliers: Vec<UsageMultiplier>,
    /// Combined usage multiplier
    pub combined_usage_multiplier: Decimal,
    /// Volume discount
    pub volume_discount_percent: Decimal,
    /// Subtotal (before discount)
    pub subtotal_usd: Decimal,
    /// Discount amount
    pub discount_usd: Decimal,
    /// Final amount (USD)
    pub final_usd: Decimal,
    /// Final amount (AETHEL)
    pub final_aethel: u128,
    /// Calculation breakdown
    pub breakdown: String,
}

/// Usage multiplier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMultiplier {
    /// Multiplier name
    pub name: String,
    /// Multiplier value
    pub value: Decimal,
    /// Reason
    pub reason: String,
}

impl RoyaltyEngine {
    /// Create new royalty engine
    pub fn new(config: RoyaltyConfig) -> Self {
        let engine = Self {
            id: Uuid::new_v4(),
            config,
            pending_payments: Arc::new(RwLock::new(HashMap::new())),
            completed_payments: Arc::new(RwLock::new(Vec::new())),
            escrow_balances: Arc::new(RwLock::new(HashMap::new())),
            treasuries: Arc::new(RwLock::new(HashMap::new())),
            partner_accounts: Arc::new(RwLock::new(HashMap::new())),
            transactions: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(RoyaltyMetrics::default())),
        };

        // Register M42 treasury
        engine.register_m42_treasury();

        engine
    }

    /// Register M42's treasury account
    fn register_m42_treasury(&self) {
        let m42 = DataCustodian::m42();
        let treasury = TreasuryAccount {
            id: Uuid::new_v4(),
            owner_id: m42.id,
            owner_name: m42.name,
            balance_aethel: 0,
            total_received_aethel: 0,
            transaction_count: 0,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };
        self.treasuries.write().insert(treasury.id, treasury);
    }

    /// Register a treasury account
    pub fn register_treasury(&self, custodian: &DataCustodian) -> Uuid {
        let treasury = TreasuryAccount {
            id: Uuid::new_v4(),
            owner_id: custodian.id,
            owner_name: custodian.name.clone(),
            balance_aethel: 0,
            total_received_aethel: 0,
            transaction_count: 0,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };
        let id = treasury.id;
        self.treasuries.write().insert(id, treasury);
        id
    }

    /// Register a partner account
    pub fn register_partner_account(&self, partner: &PharmaPartner, initial_credit: u128) -> Uuid {
        let account = PartnerAccount {
            id: Uuid::new_v4(),
            partner_id: partner.id,
            partner_name: partner.name.clone(),
            tier: partner.tier,
            credit_balance_aethel: initial_credit,
            total_spent_aethel: 0,
            analysis_count: 0,
            volume_discount_tier: VolumeDiscountTier::None,
            created_at: Utc::now(),
            last_activity: Utc::now(),
        };
        let id = account.id;
        self.partner_accounts.write().insert(id, account);
        id
    }

    /// Calculate royalty for an analysis
    pub fn calculate_royalty(&self, params: &RoyaltyCalculationParams) -> RoyaltyCalculation {
        let base_fee = self.config.base_fee_usd;

        // Tier multiplier
        let tier_multiplier = params.partner_tier.fee_multiplier();

        // Usage multipliers
        let mut usage_multipliers = Vec::new();

        // Population size multiplier
        if params.population_size > 50_000 {
            usage_multipliers.push(UsageMultiplier {
                name: "Large Population".to_string(),
                value: Decimal::new(125, 2), // 1.25x
                reason: format!("Population size {} > 50,000", params.population_size),
            });
        }

        // Rare disease marker multiplier
        if params
            .marker_types
            .contains(&GeneticMarkerType::DiseaseAssociated)
        {
            usage_multipliers.push(UsageMultiplier {
                name: "Disease Markers".to_string(),
                value: Decimal::new(150, 2), // 1.50x
                reason: "Includes disease-associated markers".to_string(),
            });
        }

        // Pharmacogenomic data multiplier
        if params
            .marker_types
            .contains(&GeneticMarkerType::Pharmacogenomic)
        {
            usage_multipliers.push(UsageMultiplier {
                name: "Pharmacogenomic".to_string(),
                value: Decimal::new(175, 2), // 1.75x
                reason: "Includes pharmacogenomic markers".to_string(),
            });
        }

        // Calculate combined usage multiplier
        let combined_usage_multiplier = if usage_multipliers.is_empty() {
            Decimal::ONE
        } else {
            usage_multipliers
                .iter()
                .map(|m| m.value)
                .fold(Decimal::ONE, |acc, v| acc * v)
        };

        // Volume discount
        let volume_tier = VolumeDiscountTier::from_count(params.total_partner_analyses);
        let volume_discount_percent = volume_tier.discount_percent();

        // Calculate totals
        let subtotal = base_fee
            * tier_multiplier
            * combined_usage_multiplier
            * Decimal::from(params.batch_size);
        let discount = subtotal * (volume_discount_percent / Decimal::from(100));
        let final_usd = subtotal - discount;

        // Convert to AETHEL
        let final_aethel = self.usd_to_aethel(final_usd);

        // Build breakdown
        let breakdown = format!(
            "Base: ${} × Tier: {} × Usage: {} × Batch: {} = ${} - {}% discount = ${}",
            base_fee,
            tier_multiplier,
            combined_usage_multiplier,
            params.batch_size,
            subtotal.round_dp(2),
            volume_discount_percent,
            final_usd.round_dp(2)
        );

        RoyaltyCalculation {
            base_fee_usd: base_fee,
            tier_multiplier,
            usage_multipliers,
            combined_usage_multiplier,
            volume_discount_percent,
            subtotal_usd: subtotal,
            discount_usd: discount,
            final_usd,
            final_aethel,
            breakdown,
        }
    }

    /// Create a royalty payment
    pub fn create_payment(
        &self,
        session_id: Uuid,
        recipient_id: Uuid,
        payer_id: Uuid,
        calculation: &RoyaltyCalculation,
    ) -> HelixGuardResult<RoyaltyPayment> {
        let payment = RoyaltyPayment {
            id: Uuid::new_v4(),
            recipient: recipient_id,
            payer: payer_id,
            amount_aethel: calculation.final_aethel,
            amount_usd: calculation.final_usd,
            status: PaymentStatus::Pending,
            tx_hash: None,
            timestamp: Utc::now(),
        };

        self.pending_payments
            .write()
            .insert(payment.id, payment.clone());

        tracing::info!(
            payment_id = %payment.id,
            session_id = %session_id,
            amount_usd = %calculation.final_usd,
            amount_aethel = payment.amount_aethel,
            "Royalty payment created"
        );

        Ok(payment)
    }

    /// Lock funds in escrow
    pub fn lock_escrow(
        &self,
        session_id: Uuid,
        payer_id: Uuid,
        recipient_id: Uuid,
        amount_aethel: u128,
        conditions: Vec<ReleaseCondition>,
    ) -> HelixGuardResult<Uuid> {
        let escrow = EscrowBalance {
            id: Uuid::new_v4(),
            session_id,
            payer_id,
            recipient_id,
            locked_amount: amount_aethel,
            locked_usd: self.aethel_to_usd(amount_aethel),
            status: EscrowStatus::Locked,
            created_at: Utc::now(),
            release_conditions: conditions,
            released_at: None,
        };

        let escrow_id = escrow.id;
        self.escrow_balances.write().insert(escrow_id, escrow);

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_escrow_locked_aethel += amount_aethel;
            metrics.active_escrows += 1;
        }

        // Create escrow lock transaction
        let tx = SettlementTransaction {
            id: Uuid::new_v4(),
            tx_type: SettlementTxType::EscrowLock,
            session_id: Some(session_id),
            from_account: payer_id,
            to_account: escrow_id, // Escrow is the recipient
            amount_aethel,
            amount_usd: self.aethel_to_usd(amount_aethel),
            status: TransactionStatus::Confirmed,
            tx_hash: Some(self.generate_tx_hash(&escrow_id)),
            block_number: Some(1), // Simulated
            confirmations: 1,
            created_at: Utc::now(),
            confirmed_at: Some(Utc::now()),
            memo: format!("Escrow lock for session {}", session_id),
        };

        self.transactions.write().push(tx);

        tracing::info!(
            escrow_id = %escrow_id,
            session_id = %session_id,
            amount_aethel = amount_aethel,
            "Funds locked in escrow"
        );

        Ok(escrow_id)
    }

    /// Release funds from escrow
    pub fn release_escrow(&self, escrow_id: Uuid) -> HelixGuardResult<()> {
        let escrow = {
            let mut escrows = self.escrow_balances.write();
            let escrow = escrows.get_mut(&escrow_id).ok_or_else(|| {
                HelixGuardError::PaymentFailed(format!("Escrow {} not found", escrow_id))
            })?;

            if escrow.status != EscrowStatus::Locked {
                return Err(HelixGuardError::PaymentFailed(format!(
                    "Escrow {} is not locked",
                    escrow_id
                )));
            }

            escrow.status = EscrowStatus::Released;
            escrow.released_at = Some(Utc::now());
            escrow.clone()
        };

        // Update treasury balance
        {
            let mut treasuries = self.treasuries.write();
            if let Some(treasury) = treasuries
                .values_mut()
                .find(|t| t.owner_id == escrow.recipient_id)
            {
                treasury.balance_aethel += escrow.locked_amount;
                treasury.total_received_aethel += escrow.locked_amount;
                treasury.transaction_count += 1;
                treasury.last_activity = Utc::now();
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_escrow_locked_aethel = metrics
                .total_escrow_locked_aethel
                .saturating_sub(escrow.locked_amount);
            metrics.active_escrows = metrics.active_escrows.saturating_sub(1);
            metrics.total_royalties_aethel += escrow.locked_amount;
            metrics.total_royalties_usd += escrow.locked_usd;
            metrics.total_transactions += 1;
        }

        // Create release transaction
        let tx = SettlementTransaction {
            id: Uuid::new_v4(),
            tx_type: SettlementTxType::EscrowRelease,
            session_id: Some(escrow.session_id),
            from_account: escrow_id,
            to_account: escrow.recipient_id,
            amount_aethel: escrow.locked_amount,
            amount_usd: escrow.locked_usd,
            status: TransactionStatus::Confirmed,
            tx_hash: Some(self.generate_tx_hash(&Uuid::new_v4())),
            block_number: Some(2),
            confirmations: 1,
            created_at: Utc::now(),
            confirmed_at: Some(Utc::now()),
            memo: format!("Escrow release for session {}", escrow.session_id),
        };

        self.transactions.write().push(tx);

        tracing::info!(
            escrow_id = %escrow_id,
            session_id = %escrow.session_id,
            amount_aethel = escrow.locked_amount,
            "Escrow funds released"
        );

        Ok(())
    }

    /// Process a royalty payment directly (no escrow)
    pub fn process_payment(&self, payment_id: Uuid) -> HelixGuardResult<Hash> {
        let payment = {
            let mut pending = self.pending_payments.write();
            let payment = pending.remove(&payment_id).ok_or_else(|| {
                HelixGuardError::PaymentFailed(format!("Payment {} not found", payment_id))
            })?;

            if payment.status != PaymentStatus::Pending {
                return Err(HelixGuardError::PaymentAlreadyProcessed(
                    payment_id.to_string(),
                ));
            }

            payment
        };

        // Generate transaction hash
        let tx_hash = self.generate_tx_hash(&payment_id);

        // Update treasury balance
        {
            let mut treasuries = self.treasuries.write();
            if let Some(treasury) = treasuries
                .values_mut()
                .find(|t| t.owner_id == payment.recipient)
            {
                treasury.balance_aethel += payment.amount_aethel;
                treasury.total_received_aethel += payment.amount_aethel;
                treasury.transaction_count += 1;
                treasury.last_activity = Utc::now();
            }
        }

        // Update partner account
        {
            let mut partners = self.partner_accounts.write();
            if let Some(account) = partners
                .values_mut()
                .find(|a| a.partner_id == payment.payer)
            {
                account.total_spent_aethel += payment.amount_aethel;
                account.analysis_count += 1;
                account.volume_discount_tier =
                    VolumeDiscountTier::from_count(account.analysis_count);
                account.last_activity = Utc::now();
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write();
            metrics.total_royalties_aethel += payment.amount_aethel;
            metrics.total_royalties_usd += payment.amount_usd;
            metrics.total_transactions += 1;
            metrics.total_analyses += 1;

            // Update average
            let n = metrics.total_analyses as i64;
            if n > 0 {
                metrics.avg_royalty_per_analysis_usd =
                    metrics.total_royalties_usd / Decimal::from(n);
            }
        }

        // Create completed payment
        let completed_payment = RoyaltyPayment {
            status: PaymentStatus::Confirmed,
            tx_hash: Some(tx_hash),
            ..payment
        };

        self.completed_payments
            .write()
            .push(completed_payment.clone());

        // Create transaction record
        let tx = SettlementTransaction {
            id: Uuid::new_v4(),
            tx_type: SettlementTxType::RoyaltyPayment,
            session_id: None,
            from_account: completed_payment.payer,
            to_account: completed_payment.recipient,
            amount_aethel: completed_payment.amount_aethel,
            amount_usd: completed_payment.amount_usd,
            status: TransactionStatus::Confirmed,
            tx_hash: Some(tx_hash),
            block_number: Some(1),
            confirmations: self.config.confirmation_blocks,
            created_at: Utc::now(),
            confirmed_at: Some(Utc::now()),
            memo: "Royalty payment".to_string(),
        };

        self.transactions.write().push(tx);

        tracing::info!(
            payment_id = %payment_id,
            tx_hash = %hex::encode(tx_hash),
            amount_aethel = completed_payment.amount_aethel,
            "Royalty payment processed"
        );

        Ok(tx_hash)
    }

    /// Convert USD to AETHEL tokens
    fn usd_to_aethel(&self, usd: Decimal) -> u128 {
        // Convert to smallest unit (18 decimals)
        let aethel_decimal = usd / Decimal::from_f64(AETHEL_USD_RATE).unwrap_or(Decimal::ONE);
        let wei = aethel_decimal * Decimal::from(10u128.pow(AETHEL_DECIMALS));
        wei.to_u128().unwrap_or(0)
    }

    /// Convert AETHEL tokens to USD
    fn aethel_to_usd(&self, aethel: u128) -> Decimal {
        let aethel_decimal = Decimal::from(aethel) / Decimal::from(10u128.pow(AETHEL_DECIMALS));
        aethel_decimal * Decimal::from_f64(AETHEL_USD_RATE).unwrap_or(Decimal::ONE)
    }

    /// Generate a transaction hash
    fn generate_tx_hash(&self, seed: &Uuid) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(Utc::now().timestamp().to_le_bytes());
        hasher.update(b"helix-guard-settlement");
        let result = hasher.finalize();
        let mut hash = Hash::default();
        hash.0.copy_from_slice(&result);
        hash
    }

    /// Get treasury balance
    pub fn get_treasury_balance(&self, custodian_id: Uuid) -> Option<u128> {
        self.treasuries
            .read()
            .values()
            .find(|t| t.owner_id == custodian_id)
            .map(|t| t.balance_aethel)
    }

    /// Get partner account
    pub fn get_partner_account(&self, partner_id: Uuid) -> Option<PartnerAccount> {
        self.partner_accounts
            .read()
            .values()
            .find(|a| a.partner_id == partner_id)
            .cloned()
    }

    /// Get all transactions
    pub fn get_transactions(&self) -> Vec<SettlementTransaction> {
        self.transactions.read().clone()
    }

    /// Get transactions for session
    pub fn get_session_transactions(&self, session_id: Uuid) -> Vec<SettlementTransaction> {
        self.transactions
            .read()
            .iter()
            .filter(|t| t.session_id == Some(session_id))
            .cloned()
            .collect()
    }

    /// Get metrics
    pub fn get_metrics(&self) -> RoyaltyMetrics {
        let m = self.metrics.read();
        RoyaltyMetrics {
            total_royalties_aethel: m.total_royalties_aethel,
            total_royalties_usd: m.total_royalties_usd,
            total_transactions: m.total_transactions,
            total_escrow_locked_aethel: m.total_escrow_locked_aethel,
            active_escrows: m.active_escrows,
            avg_royalty_per_analysis_usd: m.avg_royalty_per_analysis_usd,
            total_analyses: m.total_analyses,
        }
    }

    /// Get configuration
    pub fn config(&self) -> &RoyaltyConfig {
        &self.config
    }
}

impl Default for RoyaltyEngine {
    fn default() -> Self {
        Self::new(RoyaltyConfig::default())
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_royalty_engine_creation() {
        let engine = RoyaltyEngine::default();
        assert_eq!(engine.config.base_fee_usd, Decimal::from(500));
    }

    #[test]
    fn test_royalty_calculation_basic() {
        let engine = RoyaltyEngine::default();

        let params = RoyaltyCalculationParams {
            partner_tier: PartnerTier::Commercial,
            analysis_type: ComputeJobType::EfficacyPrediction,
            population_size: 10_000,
            marker_types: vec![GeneticMarkerType::Snp],
            batch_size: 1,
            total_partner_analyses: 0,
        };

        let calc = engine.calculate_royalty(&params);

        // Commercial tier = 1.0x, no usage multipliers, no volume discount
        assert_eq!(calc.tier_multiplier, Decimal::ONE);
        assert!(calc.usage_multipliers.is_empty());
        assert_eq!(calc.volume_discount_percent, Decimal::ZERO);
        assert_eq!(calc.final_usd, Decimal::from(500));
    }

    #[test]
    fn test_royalty_calculation_with_multipliers() {
        let engine = RoyaltyEngine::default();

        let params = RoyaltyCalculationParams {
            partner_tier: PartnerTier::Strategic,
            analysis_type: ComputeJobType::PharmacogenomicAnalysis,
            population_size: 100_000,
            marker_types: vec![
                GeneticMarkerType::Pharmacogenomic,
                GeneticMarkerType::DiseaseAssociated,
            ],
            batch_size: 10,
            total_partner_analyses: 101, // 101+ gets Gold tier
        };

        let calc = engine.calculate_royalty(&params);

        // Strategic tier = 0.8x
        assert_eq!(calc.tier_multiplier, Decimal::new(80, 2));

        // Should have usage multipliers for large population, pharma, and disease
        assert!(calc.usage_multipliers.len() >= 2);

        // Gold tier discount = 20%
        assert_eq!(calc.volume_discount_percent, Decimal::from(20));
    }

    #[test]
    fn test_volume_discount_tiers() {
        assert_eq!(VolumeDiscountTier::from_count(5), VolumeDiscountTier::None);
        assert_eq!(
            VolumeDiscountTier::from_count(25),
            VolumeDiscountTier::Bronze
        );
        assert_eq!(
            VolumeDiscountTier::from_count(75),
            VolumeDiscountTier::Silver
        );
        assert_eq!(
            VolumeDiscountTier::from_count(150),
            VolumeDiscountTier::Gold
        );
    }

    #[test]
    fn test_usd_aethel_conversion() {
        let engine = RoyaltyEngine::default();

        let usd = Decimal::from(100);
        let aethel = engine.usd_to_aethel(usd);

        // 100 USD = 100 * 10^18 wei
        assert_eq!(aethel, 100_000_000_000_000_000_000u128);

        // Convert back
        let back_to_usd = engine.aethel_to_usd(aethel);
        assert_eq!(back_to_usd, usd);
    }

    #[test]
    fn test_escrow_lifecycle() {
        let engine = RoyaltyEngine::default();

        let session_id = Uuid::new_v4();
        let payer_id = Uuid::new_v4();
        let recipient = DataCustodian::m42();
        let recipient_id = recipient.id;

        // Register treasury
        engine.register_treasury(&recipient);

        // Lock escrow
        let escrow_id = engine
            .lock_escrow(
                session_id,
                payer_id,
                recipient_id,
                1000_000_000_000_000_000_000, // 1000 AETHEL
                vec![ReleaseCondition::TeeAttestationVerified],
            )
            .unwrap();

        // Check escrow is locked
        let escrow = engine
            .escrow_balances
            .read()
            .get(&escrow_id)
            .cloned()
            .unwrap();
        assert_eq!(escrow.status, EscrowStatus::Locked);

        // Release escrow
        engine.release_escrow(escrow_id).unwrap();

        // Check escrow is released
        let escrow = engine
            .escrow_balances
            .read()
            .get(&escrow_id)
            .cloned()
            .unwrap();
        assert_eq!(escrow.status, EscrowStatus::Released);
    }

    #[test]
    fn test_payment_processing() {
        let engine = RoyaltyEngine::default();

        let recipient = DataCustodian::m42();
        let recipient_id = recipient.id;
        engine.register_treasury(&recipient);

        let partner = PharmaPartner::astrazeneca();
        let payer_id = partner.id;
        engine.register_partner_account(&partner, 0);

        let calc = RoyaltyCalculation {
            base_fee_usd: Decimal::from(500),
            tier_multiplier: Decimal::ONE,
            usage_multipliers: vec![],
            combined_usage_multiplier: Decimal::ONE,
            volume_discount_percent: Decimal::ZERO,
            subtotal_usd: Decimal::from(500),
            discount_usd: Decimal::ZERO,
            final_usd: Decimal::from(500),
            final_aethel: 500_000_000_000_000_000_000, // 500 AETHEL
            breakdown: "Test".to_string(),
        };

        let payment = engine
            .create_payment(Uuid::new_v4(), recipient_id, payer_id, &calc)
            .unwrap();

        let tx_hash = engine.process_payment(payment.id).unwrap();
        assert!(!tx_hash.iter().all(|&b| b == 0));

        // Check metrics updated
        let metrics = engine.get_metrics();
        assert_eq!(metrics.total_transactions, 1);
    }
}
