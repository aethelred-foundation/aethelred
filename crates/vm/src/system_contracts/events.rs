//! System Contract Events
//!
//! Event definitions emitted by system contracts for indexing and notifications.

use super::slashing::OffenseType;
use super::tokenomics::AllocationCategory;
use super::types::{Address, Hash, JobId, StakeRole, TokenAmount};
use serde::{Deserialize, Serialize};
// Note: HardwareTier is used as u8 in PoUWEvent to avoid circular dependency

// =============================================================================
// EVENT ENVELOPE
// =============================================================================

/// System event wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemEvent {
    /// Job-related event
    Job(JobEvent),
    /// Staking-related event
    Staking(StakingEvent),
    /// Compliance-related event
    Compliance(ComplianceEvent),
    /// Bank/token-related event
    Bank(BankEvent),
    /// Slashing-related event
    Slashing(SlashingEvent),
    /// Tokenomics-related event
    Tokenomics(TokenomicsEvent),
    /// Proof-of-Useful-Work event
    PoUW(PoUWEvent),
}

impl SystemEvent {
    /// Get event type name
    pub fn event_type(&self) -> &'static str {
        match self {
            SystemEvent::Job(e) => e.event_type(),
            SystemEvent::Staking(e) => e.event_type(),
            SystemEvent::Compliance(e) => e.event_type(),
            SystemEvent::Bank(e) => e.event_type(),
            SystemEvent::Slashing(e) => e.event_type(),
            SystemEvent::Tokenomics(e) => e.event_type(),
            SystemEvent::PoUW(e) => e.event_type(),
        }
    }

    /// Get event topic (for log filtering)
    pub fn topic(&self) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.event_type().as_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

// =============================================================================
// JOB EVENTS
// =============================================================================

/// Job-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobEvent {
    /// New job submitted
    JobSubmitted {
        job_id: JobId,
        requester: Address,
        model_hash: Hash,
        bid_amount: TokenAmount,
        sla_deadline: u64,
        block_height: u64,
    },

    /// Job assigned to prover
    JobAssigned {
        job_id: JobId,
        prover: Address,
        assigned_at: u64,
        block_height: u64,
    },

    /// Prover started working on job
    JobStarted {
        job_id: JobId,
        prover: Address,
        started_at: u64,
    },

    /// Proof submitted for job
    ProofSubmitted {
        job_id: JobId,
        prover: Address,
        output_hash: Hash,
        verification_method: u8,
        block_height: u64,
    },

    /// Job verified successfully
    JobVerified {
        job_id: JobId,
        prover: Address,
        verified_at: u64,
    },

    /// Job settled and rewards distributed
    JobSettled {
        job_id: JobId,
        prover: Address,
        requester: Address,
        prover_reward: TokenAmount,
        validator_reward: TokenAmount,
        burned: TokenAmount,
        block_height: u64,
    },

    /// Job expired (SLA timeout)
    JobExpired {
        job_id: JobId,
        prover: Address,
        deadline: u64,
        expired_at: u64,
        slashed_amount: TokenAmount,
    },

    /// Job cancelled by requester
    JobCancelled {
        job_id: JobId,
        requester: Address,
        refunded: TokenAmount,
        cancellation_fee: TokenAmount,
        block_height: u64,
    },

    /// Job failed verification
    JobFailed {
        job_id: JobId,
        prover: Address,
        reason: String,
        slashed_amount: TokenAmount,
    },

    /// Job disputed
    JobDisputed {
        job_id: JobId,
        disputer: Address,
        reason: String,
        dispute_bond: TokenAmount,
    },

    /// Dispute resolved
    DisputeResolved {
        job_id: JobId,
        winner: Address,
        resolution: String,
    },
}

impl JobEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            JobEvent::JobSubmitted { .. } => "JobSubmitted",
            JobEvent::JobAssigned { .. } => "JobAssigned",
            JobEvent::JobStarted { .. } => "JobStarted",
            JobEvent::ProofSubmitted { .. } => "ProofSubmitted",
            JobEvent::JobVerified { .. } => "JobVerified",
            JobEvent::JobSettled { .. } => "JobSettled",
            JobEvent::JobExpired { .. } => "JobExpired",
            JobEvent::JobCancelled { .. } => "JobCancelled",
            JobEvent::JobFailed { .. } => "JobFailed",
            JobEvent::JobDisputed { .. } => "JobDisputed",
            JobEvent::DisputeResolved { .. } => "DisputeResolved",
        }
    }

    /// Get job ID from event
    pub fn job_id(&self) -> &JobId {
        match self {
            JobEvent::JobSubmitted { job_id, .. } => job_id,
            JobEvent::JobAssigned { job_id, .. } => job_id,
            JobEvent::JobStarted { job_id, .. } => job_id,
            JobEvent::ProofSubmitted { job_id, .. } => job_id,
            JobEvent::JobVerified { job_id, .. } => job_id,
            JobEvent::JobSettled { job_id, .. } => job_id,
            JobEvent::JobExpired { job_id, .. } => job_id,
            JobEvent::JobCancelled { job_id, .. } => job_id,
            JobEvent::JobFailed { job_id, .. } => job_id,
            JobEvent::JobDisputed { job_id, .. } => job_id,
            JobEvent::DisputeResolved { job_id, .. } => job_id,
        }
    }
}

// =============================================================================
// STAKING EVENTS
// =============================================================================

/// Staking-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StakingEvent {
    /// Tokens staked
    Staked {
        staker: Address,
        amount: TokenAmount,
        role: StakeRole,
        total_stake: TokenAmount,
        block_height: u64,
    },

    /// Unstake initiated
    UnstakeInitiated {
        staker: Address,
        amount: TokenAmount,
        unlock_time: u64,
        block_height: u64,
    },

    /// Stake withdrawn
    StakeWithdrawn {
        staker: Address,
        amount: TokenAmount,
        block_height: u64,
    },

    /// Stake slashed
    Slashed {
        staker: Address,
        amount: TokenAmount,
        reason: String,
        job_id: Option<JobId>,
        block_height: u64,
    },

    /// Rewards distributed
    RewardsDistributed {
        staker: Address,
        amount: TokenAmount,
        source: String,
        block_height: u64,
    },

    /// Tokens burned
    TokensBurned {
        amount: TokenAmount,
        reason: String,
        block_height: u64,
    },

    /// Network utilization updated
    UtilizationUpdated {
        old_utilization: u8,
        new_utilization: u8,
        new_burn_rate: u8,
        block_height: u64,
    },

    /// Delegation created
    Delegated {
        delegator: Address,
        validator: Address,
        amount: TokenAmount,
        block_height: u64,
    },

    /// Delegation removed
    Undelegated {
        delegator: Address,
        validator: Address,
        amount: TokenAmount,
        block_height: u64,
    },

    /// Validator jailed
    ValidatorJailed {
        validator: Address,
        reason: String,
        until: u64,
        block_height: u64,
    },

    /// Validator unjailed
    ValidatorUnjailed {
        validator: Address,
        block_height: u64,
    },
}

impl StakingEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            StakingEvent::Staked { .. } => "Staked",
            StakingEvent::UnstakeInitiated { .. } => "UnstakeInitiated",
            StakingEvent::StakeWithdrawn { .. } => "StakeWithdrawn",
            StakingEvent::Slashed { .. } => "Slashed",
            StakingEvent::RewardsDistributed { .. } => "RewardsDistributed",
            StakingEvent::TokensBurned { .. } => "TokensBurned",
            StakingEvent::UtilizationUpdated { .. } => "UtilizationUpdated",
            StakingEvent::Delegated { .. } => "Delegated",
            StakingEvent::Undelegated { .. } => "Undelegated",
            StakingEvent::ValidatorJailed { .. } => "ValidatorJailed",
            StakingEvent::ValidatorUnjailed { .. } => "ValidatorUnjailed",
        }
    }
}

// =============================================================================
// COMPLIANCE EVENTS
// =============================================================================

/// Compliance-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceEvent {
    /// Transaction blocked by compliance
    TransactionBlocked {
        tx_hash: Hash,
        sender: Address,
        receiver: Address,
        reason: String,
        module: String,
        block_height: u64,
    },

    /// Entity certified
    EntityCertified {
        entity: Address,
        did: String,
        certification: String,
        expires_at: u64,
        certifier: Address,
        block_height: u64,
    },

    /// Certification revoked
    CertificationRevoked {
        entity: Address,
        certification: String,
        reason: String,
        revoker: Address,
        block_height: u64,
    },

    /// Sanctions list updated
    SanctionsUpdated {
        added_count: u32,
        removed_count: u32,
        authority: Address,
        block_height: u64,
    },

    /// Compliance module enabled/disabled
    ModuleStatusChanged {
        module: String,
        enabled: bool,
        block_height: u64,
    },

    /// Compliance check passed (audit trail)
    ComplianceCheckPassed {
        tx_hash: Hash,
        sender: Address,
        tags: Vec<String>,
        checks_performed: Vec<String>,
        block_height: u64,
    },

    // =========================================================================
    // NEW: Events used by the ComplianceModule implementation
    // =========================================================================
    /// Certification added for an entity
    CertificationAdded {
        entity: Address,
        standard: u8,
        expires_at: u64,
    },

    /// Address added to sanctions list
    AddressSanctioned { address: Address, list: String },

    /// Address removed from sanctions list
    AddressUnsanctioned { address: Address },

    /// Sanctions list bulk update
    SanctionsListUpdated { list: String, count: u32 },

    /// Consent revoked
    ConsentRevoked {
        data_subject: Address,
        data_controller: Address,
    },

    /// Business Associate Agreement registered
    BaaRegistered {
        covered_entity: Address,
        business_associate: Address,
    },

    /// Compliance check performed
    CheckPerformed {
        check_id: Hash,
        requester: Address,
        passed: bool,
        risk_score: u8,
    },
}

impl ComplianceEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            ComplianceEvent::TransactionBlocked { .. } => "TransactionBlocked",
            ComplianceEvent::EntityCertified { .. } => "EntityCertified",
            ComplianceEvent::CertificationRevoked { .. } => "CertificationRevoked",
            ComplianceEvent::SanctionsUpdated { .. } => "SanctionsUpdated",
            ComplianceEvent::ModuleStatusChanged { .. } => "ModuleStatusChanged",
            ComplianceEvent::ComplianceCheckPassed { .. } => "ComplianceCheckPassed",
            ComplianceEvent::CertificationAdded { .. } => "CertificationAdded",
            ComplianceEvent::AddressSanctioned { .. } => "AddressSanctioned",
            ComplianceEvent::AddressUnsanctioned { .. } => "AddressUnsanctioned",
            ComplianceEvent::SanctionsListUpdated { .. } => "SanctionsListUpdated",
            ComplianceEvent::ConsentRevoked { .. } => "ConsentRevoked",
            ComplianceEvent::BaaRegistered { .. } => "BaaRegistered",
            ComplianceEvent::CheckPerformed { .. } => "CheckPerformed",
        }
    }
}

// =============================================================================
// BANK EVENTS
// =============================================================================

/// Bank/token-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BankEvent {
    /// Transfer executed
    Transfer {
        from: Address,
        to: Address,
        amount: TokenAmount,
        block_height: u64,
    },

    /// Escrow created
    EscrowCreated {
        escrow_id: Hash,
        from: Address,
        amount: TokenAmount,
        release_conditions: String,
        block_height: u64,
    },

    /// Escrow released
    EscrowReleased {
        escrow_id: Hash,
        to: Address,
        amount: TokenAmount,
        block_height: u64,
    },

    /// Escrow refunded
    EscrowRefunded {
        escrow_id: Hash,
        to: Address,
        amount: TokenAmount,
        reason: String,
        block_height: u64,
    },

    /// Account locked
    AccountLocked {
        account: Address,
        until: u64,
        reason: String,
        block_height: u64,
    },

    /// Account unlocked
    AccountUnlocked { account: Address, block_height: u64 },
}

impl BankEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            BankEvent::Transfer { .. } => "Transfer",
            BankEvent::EscrowCreated { .. } => "EscrowCreated",
            BankEvent::EscrowReleased { .. } => "EscrowReleased",
            BankEvent::EscrowRefunded { .. } => "EscrowRefunded",
            BankEvent::AccountLocked { .. } => "AccountLocked",
            BankEvent::AccountUnlocked { .. } => "AccountUnlocked",
        }
    }
}

// =============================================================================
// SLASHING EVENTS
// =============================================================================

/// Slashing-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvent {
    /// Stake slashed for offense
    Slashed {
        offender: Address,
        offense_type: OffenseType,
        slash_amount: TokenAmount,
        burn_amount: TokenAmount,
        reporter_reward: TokenAmount,
        reporter: Option<Address>,
        ban_until: u64,
        tombstoned: bool,
        evidence_hash: Hash,
    },

    /// Challenge submitted against a prover
    ChallengeSubmitted {
        challenge_id: Hash,
        challenger: Address,
        prover: Address,
        job_id: JobId,
        committee: Vec<Address>,
    },

    /// Challenge resolved - prover was at fault
    ChallengeResolvedProverFault {
        challenge_id: Hash,
        prover: Address,
        challenger: Address,
        slash_amount: TokenAmount,
        challenger_reward: TokenAmount,
    },

    /// Challenge resolved - challenger was wrong (spam)
    ChallengeResolvedChallengerFault {
        challenge_id: Hash,
        challenger: Address,
        prover: Address,
        spam_penalty: TokenAmount,
    },

    /// Spam challenge penalty applied
    SpamChallengePenalty {
        challenger: Address,
        penalty_amount: TokenAmount,
        challenge_id: Hash,
    },

    /// Attestation challenge issued to a node
    AttestationChallengeIssued {
        challenge_id: Hash,
        target: Address,
        deadline: u64,
    },

    /// Attestation challenge response received
    AttestationResponseReceived {
        challenge_id: Hash,
        target: Address,
        verified: bool,
    },

    /// Attestation challenge failed (no response)
    AttestationChallengeFailed {
        challenge_id: Hash,
        target: Address,
        slash_amount: TokenAmount,
    },

    /// Double sign detected
    DoubleSignDetected {
        offender: Address,
        height: u64,
        evidence_hash: Hash,
    },

    /// Equivocation detected
    EquivocationDetected {
        offender: Address,
        height: u64,
        round: u32,
        evidence_hash: Hash,
    },

    /// Node tombstoned (permanently banned)
    NodeTombstoned {
        offender: Address,
        offense_type: OffenseType,
        total_slashed: TokenAmount,
    },

    /// Node ban expired
    BanExpired { node: Address },

    /// Reliability score updated
    ReliabilityScoreUpdated {
        node: Address,
        old_score: u16,
        new_score: u16,
        below_threshold: bool,
    },
}

impl SlashingEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            SlashingEvent::Slashed { .. } => "Slashed",
            SlashingEvent::ChallengeSubmitted { .. } => "ChallengeSubmitted",
            SlashingEvent::ChallengeResolvedProverFault { .. } => "ChallengeResolvedProverFault",
            SlashingEvent::ChallengeResolvedChallengerFault { .. } => {
                "ChallengeResolvedChallengerFault"
            }
            SlashingEvent::SpamChallengePenalty { .. } => "SpamChallengePenalty",
            SlashingEvent::AttestationChallengeIssued { .. } => "AttestationChallengeIssued",
            SlashingEvent::AttestationResponseReceived { .. } => "AttestationResponseReceived",
            SlashingEvent::AttestationChallengeFailed { .. } => "AttestationChallengeFailed",
            SlashingEvent::DoubleSignDetected { .. } => "DoubleSignDetected",
            SlashingEvent::EquivocationDetected { .. } => "EquivocationDetected",
            SlashingEvent::NodeTombstoned { .. } => "NodeTombstoned",
            SlashingEvent::BanExpired { .. } => "BanExpired",
            SlashingEvent::ReliabilityScoreUpdated { .. } => "ReliabilityScoreUpdated",
        }
    }
}

// =============================================================================
// TOKENOMICS EVENTS
// =============================================================================

/// Tokenomics-related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenomicsEvent {
    /// Genesis initialized
    GenesisInitialized {
        total_supply: TokenAmount,
        circulating: TokenAmount,
        locked: TokenAmount,
    },

    /// Vesting position created
    VestingPositionCreated {
        position_id: u64,
        beneficiary: Address,
        amount: TokenAmount,
        category: AllocationCategory,
    },

    /// Vested tokens claimed
    VestingClaimed {
        position_id: u64,
        beneficiary: Address,
        amount: TokenAmount,
    },

    /// Vesting position revoked
    VestingRevoked {
        position_id: u64,
        unvested_returned: TokenAmount,
    },

    /// Mining emission distributed
    MiningEmission {
        amount: TokenAmount,
        total_emitted: TokenAmount,
    },

    /// Halving occurred
    HalvingOccurred {
        period: u32,
        old_rate: TokenAmount,
        new_rate: TokenAmount,
    },

    /// Tokens burned via adaptive burn
    AdaptiveBurn {
        amount: TokenAmount,
        block_fullness_bps: u16,
        effective_rate_bps: u16,
        total_burned: TokenAmount,
    },

    /// Fee distributed
    FeeDistributed {
        total_fee: TokenAmount,
        prover_amount: TokenAmount,
        validator_amount: TokenAmount,
        burn_amount: TokenAmount,
    },

    /// Burn rate updated
    BurnRateUpdated {
        old_rate_bps: u16,
        new_rate_bps: u16,
        utilization_bps: u16,
    },

    /// Supply metrics updated
    SupplyUpdated {
        circulating: TokenAmount,
        burned: TokenAmount,
        locked: TokenAmount,
    },

    /// DAO unlock approved
    DaoUnlockApproved {
        recipient: Address,
        amount: TokenAmount,
        proposal_id: u64,
    },

    /// Foundation reserve deployed
    FoundationDeployment {
        recipient: Address,
        amount: TokenAmount,
        purpose: String,
    },
}

impl TokenomicsEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            TokenomicsEvent::GenesisInitialized { .. } => "GenesisInitialized",
            TokenomicsEvent::VestingPositionCreated { .. } => "VestingPositionCreated",
            TokenomicsEvent::VestingClaimed { .. } => "VestingClaimed",
            TokenomicsEvent::VestingRevoked { .. } => "VestingRevoked",
            TokenomicsEvent::MiningEmission { .. } => "MiningEmission",
            TokenomicsEvent::HalvingOccurred { .. } => "HalvingOccurred",
            TokenomicsEvent::AdaptiveBurn { .. } => "AdaptiveBurn",
            TokenomicsEvent::FeeDistributed { .. } => "FeeDistributed",
            TokenomicsEvent::BurnRateUpdated { .. } => "BurnRateUpdated",
            TokenomicsEvent::SupplyUpdated { .. } => "SupplyUpdated",
            TokenomicsEvent::DaoUnlockApproved { .. } => "DaoUnlockApproved",
            TokenomicsEvent::FoundationDeployment { .. } => "FoundationDeployment",
        }
    }
}

// =============================================================================
// PROOF-OF-USEFUL-WORK EVENTS
// =============================================================================

/// Proof-of-Useful-Work (PoUW) engine events
///
/// Events for the 4 Economic Moats:
/// 1. Compute-Weighted Multiplier (Anti-Whale)
/// 2. Regulatory Bonding Curves (Compliance-as-an-Asset)
/// 3. Congestion-Squared Deflation (Burning²)
/// 4. Sovereignty Premium (Oracle Pricing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoUWEvent {
    // =========================================================================
    // MOAT 1: COMPUTE-WEIGHTED MULTIPLIER EVENTS
    // =========================================================================
    /// Compute multiplier updated for a node
    ComputeMultiplierUpdated {
        /// Node address
        node: Address,
        /// Previous multiplier (basis points, 1000 = 1.0x)
        old_multiplier_bps: u16,
        /// New multiplier (basis points)
        new_multiplier_bps: u16,
        /// Verified operations in 30-day window
        verified_ops_30d: u128,
        /// Hardware tier (0=Entry, 1=Basic, 2=Standard, 3=Professional, 4=Enterprise)
        hardware_tier: u8,
    },

    /// Compute operation verified and recorded
    ComputeOperationVerified {
        /// Operation ID
        operation_id: Hash,
        /// Node that performed the computation
        node: Address,
        /// Job ID
        job_id: JobId,
        /// Number of verified operations
        verified_ops: u128,
        /// TEE type used
        tee_type: u8,
        /// Was ZK proof verified
        zk_verified: bool,
    },

    /// Hardware tier upgraded
    HardwareTierUpgraded {
        /// Node address
        node: Address,
        /// Previous tier
        old_tier: u8,
        /// New tier
        new_tier: u8,
        /// Total verified ops that triggered upgrade
        total_ops: u128,
    },

    /// Epoch reward calculated with compute weight
    ComputeWeightedRewardCalculated {
        /// Node address
        node: Address,
        /// Base reward (without multiplier)
        base_reward: TokenAmount,
        /// Final reward (with multiplier)
        final_reward: TokenAmount,
        /// Applied multiplier (basis points)
        multiplier_bps: u16,
        /// Tier bonus applied (basis points)
        tier_bonus_bps: u16,
    },

    // =========================================================================
    // MOAT 2: COMPLIANCE BOND EVENTS
    // =========================================================================
    /// Compliance bond posted
    ComplianceBondPosted {
        /// Bond ID
        bond_id: Hash,
        /// Node that posted the bond
        node: Address,
        /// Bond type (1=GDPR, 2=HIPAA, 3=Financial, etc.)
        bond_type: u8,
        /// Bond amount in AETHEL wei
        amount: TokenAmount,
        /// Expiry timestamp (0 = no expiry)
        expires_at: u64,
    },

    /// Compliance bond released (returned to node)
    ComplianceBondReleased {
        /// Bond ID
        bond_id: Hash,
        /// Node that receives the bond back
        node: Address,
        /// Amount returned
        amount: TokenAmount,
    },

    /// Compliance bond liquidated (TEE attestation failure)
    ComplianceBondLiquidated {
        /// Liquidation ID
        liquidation_id: Hash,
        /// Bond that was liquidated
        bond_id: Hash,
        /// Node that was slashed
        node: Address,
        /// Victim (data owner)
        victim: Address,
        /// Total bond amount
        bond_amount: TokenAmount,
        /// Amount paid to victim (80%)
        victim_payout: TokenAmount,
        /// Amount burned (20%)
        burned: TokenAmount,
        /// Reason code
        reason: u8,
    },

    /// Node entered compliance cooldown
    ComplianceCooldownStarted {
        /// Node address
        node: Address,
        /// Cooldown ends at
        cooldown_until: u64,
        /// Reason
        reason: String,
    },

    /// Node compliance cooldown expired
    ComplianceCooldownExpired {
        /// Node address
        node: Address,
    },

    // =========================================================================
    // MOAT 3: CONGESTION-SQUARED DEFLATION EVENTS
    // =========================================================================
    /// Burn rate updated due to congestion
    BurnRateUpdated {
        /// Previous burn rate (basis points)
        old_rate_bps: u16,
        /// New burn rate (basis points)
        new_rate_bps: u16,
        /// Current network load (basis points, 10000 = 100%)
        network_load_bps: u16,
        /// Total tokens burned
        total_burned: TokenAmount,
    },

    /// Fee processed with congestion-squared burn
    FeeProcessed {
        /// Total fee amount
        total_fee: TokenAmount,
        /// Amount to prover (70%)
        prover_amount: TokenAmount,
        /// Amount to validator
        validator_amount: TokenAmount,
        /// Amount burned
        burn_amount: TokenAmount,
        /// Burn rate applied (basis points)
        burn_rate_bps: u16,
        /// Network load at time of processing
        network_load_bps: u16,
    },

    /// Significant burn event (large transaction)
    SignificantBurn {
        /// Amount burned
        amount: TokenAmount,
        /// Transaction hash that triggered burn
        tx_hash: Hash,
        /// Burn rate at time (basis points)
        burn_rate_bps: u16,
        /// New total burned
        total_burned: TokenAmount,
    },

    /// Congestion spike detected
    CongestionSpikeDetected {
        /// Previous load (basis points)
        previous_load_bps: u16,
        /// Current load (basis points)
        current_load_bps: u16,
        /// New burn rate (basis points)
        new_burn_rate_bps: u16,
        /// Block height
        block_height: u64,
    },

    // =========================================================================
    // MOAT 4: SOVEREIGNTY PREMIUM EVENTS
    // =========================================================================
    /// Sovereignty premium charged for data access
    SovereigntyPremiumCharged {
        /// Request ID
        request_id: Hash,
        /// Requester address
        requester: Address,
        /// Data provider address
        provider: Address,
        /// Region code (0=Public, 1=EU, 2=UAE, 3=SG, etc.)
        region: u8,
        /// Verification level
        verification_level: u8,
        /// Data category
        category: u8,
        /// Base price
        base_price: TokenAmount,
        /// Applied premium multiplier (basis points)
        premium_multiplier_bps: u16,
        /// Final price charged
        final_price: TokenAmount,
    },

    /// New data provider registered
    DataProviderRegistered {
        /// Provider address
        provider: Address,
        /// Regions they serve
        regions: Vec<u8>,
        /// Verification level
        verification_level: u8,
    },

    /// Provider earned sovereignty premium
    ProviderPremiumEarned {
        /// Provider address
        provider: Address,
        /// Amount earned
        amount: TokenAmount,
        /// Region of data
        region: u8,
        /// Total earnings
        total_earnings: TokenAmount,
    },

    // =========================================================================
    // EPOCH EVENTS
    // =========================================================================
    /// New epoch started
    EpochStarted {
        /// Epoch number
        epoch: u64,
        /// Timestamp
        timestamp: u64,
        /// Starting burn rate
        burn_rate_bps: u16,
    },

    /// Epoch ended
    EpochEnded {
        /// Epoch number
        epoch: u64,
        /// Timestamp
        timestamp: u64,
        /// Total burned this epoch
        total_burned: TokenAmount,
        /// Total rewards distributed
        total_rewards_distributed: TokenAmount,
    },

    /// PoUW engine statistics snapshot
    StatsSnapshot {
        /// Block height
        block_height: u64,
        /// Number of compute nodes
        compute_nodes: u32,
        /// Total verified ops (30-day)
        total_compute_ops_30d: u128,
        /// Active compliance bonds
        active_compliance_bonds: u64,
        /// Total bond value
        total_bond_value: TokenAmount,
        /// Current burn rate
        burn_rate_bps: u16,
        /// Network load
        network_load_bps: u16,
        /// Total burned all time
        total_burned: TokenAmount,
    },
}

impl PoUWEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            // Moat 1: Compute
            PoUWEvent::ComputeMultiplierUpdated { .. } => "ComputeMultiplierUpdated",
            PoUWEvent::ComputeOperationVerified { .. } => "ComputeOperationVerified",
            PoUWEvent::HardwareTierUpgraded { .. } => "HardwareTierUpgraded",
            PoUWEvent::ComputeWeightedRewardCalculated { .. } => "ComputeWeightedRewardCalculated",
            // Moat 2: Compliance Bonds
            PoUWEvent::ComplianceBondPosted { .. } => "ComplianceBondPosted",
            PoUWEvent::ComplianceBondReleased { .. } => "ComplianceBondReleased",
            PoUWEvent::ComplianceBondLiquidated { .. } => "ComplianceBondLiquidated",
            PoUWEvent::ComplianceCooldownStarted { .. } => "ComplianceCooldownStarted",
            PoUWEvent::ComplianceCooldownExpired { .. } => "ComplianceCooldownExpired",
            // Moat 3: Burn
            PoUWEvent::BurnRateUpdated { .. } => "BurnRateUpdated",
            PoUWEvent::FeeProcessed { .. } => "FeeProcessed",
            PoUWEvent::SignificantBurn { .. } => "SignificantBurn",
            PoUWEvent::CongestionSpikeDetected { .. } => "CongestionSpikeDetected",
            // Moat 4: Sovereignty
            PoUWEvent::SovereigntyPremiumCharged { .. } => "SovereigntyPremiumCharged",
            PoUWEvent::DataProviderRegistered { .. } => "DataProviderRegistered",
            PoUWEvent::ProviderPremiumEarned { .. } => "ProviderPremiumEarned",
            // Epoch
            PoUWEvent::EpochStarted { .. } => "EpochStarted",
            PoUWEvent::EpochEnded { .. } => "EpochEnded",
            PoUWEvent::StatsSnapshot { .. } => "StatsSnapshot",
        }
    }

    /// Get the moat this event belongs to
    pub fn moat(&self) -> &'static str {
        match self {
            PoUWEvent::ComputeMultiplierUpdated { .. }
            | PoUWEvent::ComputeOperationVerified { .. }
            | PoUWEvent::HardwareTierUpgraded { .. }
            | PoUWEvent::ComputeWeightedRewardCalculated { .. } => "COMPUTE_WEIGHTED",

            PoUWEvent::ComplianceBondPosted { .. }
            | PoUWEvent::ComplianceBondReleased { .. }
            | PoUWEvent::ComplianceBondLiquidated { .. }
            | PoUWEvent::ComplianceCooldownStarted { .. }
            | PoUWEvent::ComplianceCooldownExpired { .. } => "COMPLIANCE_BOND",

            PoUWEvent::BurnRateUpdated { .. }
            | PoUWEvent::FeeProcessed { .. }
            | PoUWEvent::SignificantBurn { .. }
            | PoUWEvent::CongestionSpikeDetected { .. } => "CONGESTION_BURN",

            PoUWEvent::SovereigntyPremiumCharged { .. }
            | PoUWEvent::DataProviderRegistered { .. }
            | PoUWEvent::ProviderPremiumEarned { .. } => "SOVEREIGNTY_PREMIUM",

            PoUWEvent::EpochStarted { .. }
            | PoUWEvent::EpochEnded { .. }
            | PoUWEvent::StatsSnapshot { .. } => "EPOCH",
        }
    }
}

// =============================================================================
// EVENT LOG
// =============================================================================

/// Event with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLog {
    /// Event index in block
    pub index: u32,
    /// Block height
    pub block_height: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Transaction hash (if from tx)
    pub tx_hash: Option<Hash>,
    /// Event data
    pub event: SystemEvent,
}

impl EventLog {
    /// Create new event log with full parameters
    pub fn new_full(
        index: u32,
        block_height: u64,
        timestamp: u64,
        tx_hash: Option<Hash>,
        event: SystemEvent,
    ) -> Self {
        Self {
            index,
            block_height,
            timestamp,
            tx_hash,
            event,
        }
    }

    /// Create new event log with just the event (used by compliance module)
    /// Uses current system time and placeholder values for index/block
    pub fn new(event: SystemEvent) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            index: 0,
            block_height: 0,
            timestamp,
            tx_hash: None,
            event,
        }
    }

    /// Set the block context
    pub fn with_block_context(mut self, block_height: u64, timestamp: u64, index: u32) -> Self {
        self.block_height = block_height;
        self.timestamp = timestamp;
        self.index = index;
        self
    }

    /// Set the transaction hash
    pub fn with_tx_hash(mut self, tx_hash: Hash) -> Self {
        self.tx_hash = Some(tx_hash);
        self
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_types() {
        let job_event = JobEvent::JobSubmitted {
            job_id: [0u8; 32],
            requester: [1u8; 32],
            model_hash: [2u8; 32],
            bid_amount: 1000,
            sla_deadline: 12345,
            block_height: 100,
        };

        assert_eq!(job_event.event_type(), "JobSubmitted");

        let system_event = SystemEvent::Job(job_event);
        assert_eq!(system_event.event_type(), "JobSubmitted");
    }

    #[test]
    fn test_event_topic() {
        let event1 = SystemEvent::Job(JobEvent::JobSubmitted {
            job_id: [0u8; 32],
            requester: [1u8; 32],
            model_hash: [2u8; 32],
            bid_amount: 1000,
            sla_deadline: 12345,
            block_height: 100,
        });

        let event2 = SystemEvent::Job(JobEvent::JobSettled {
            job_id: [0u8; 32],
            prover: [1u8; 32],
            requester: [2u8; 32],
            prover_reward: 700,
            validator_reward: 250,
            burned: 50,
            block_height: 100,
        });

        // Different event types should have different topics
        assert_ne!(event1.topic(), event2.topic());
    }

    #[test]
    fn test_job_event_id() {
        let job_id = [42u8; 32];
        let event = JobEvent::JobVerified {
            job_id,
            prover: [1u8; 32],
            verified_at: 12345,
        };

        assert_eq!(event.job_id(), &job_id);
    }
}
