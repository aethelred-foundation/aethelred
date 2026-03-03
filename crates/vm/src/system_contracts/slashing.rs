//! # Aethelred Slashing Engine
//!
//! Enterprise-grade security enforcement module implementing three-tier offense
//! classification with automated on-chain punishments for the Proof-of-Compute network.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────┐
//! │                           SLASHING ENGINE                                        │
//! ├─────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                  │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                      OFFENSE CLASSIFICATION                                │ │
//! │  │                                                                            │ │
//! │  │  ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐        │ │
//! │  │  │    TIER 1         │ │    TIER 2         │ │    TIER 3         │        │ │
//! │  │  │   CRITICAL        │ │   MALICIOUS       │ │   PERFORMANCE     │        │ │
//! │  │  ├───────────────────┤ ├───────────────────┤ ├───────────────────┤        │ │
//! │  │  │ • Invalid Proof   │ │ • Double Sign     │ │ • SLA Timeout     │        │ │
//! │  │  │ • Forged TEE Sig  │ │ • Equivocation    │ │ • Late Delivery   │        │ │
//! │  │  │ • Hardware Spoof  │ │ • Vote Tampering  │ │ • Partial Results │        │ │
//! │  │  ├───────────────────┤ ├───────────────────┤ ├───────────────────┤        │ │
//! │  │  │ Penalty: 100%     │ │ Penalty: 50%      │ │ Penalty: 5%       │        │ │
//! │  │  │ + Tombstone       │ │ + 30 Day Ban      │ │ + 24h Suspend     │        │ │
//! │  │  └───────────────────┘ └───────────────────┘ └───────────────────┘        │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                      │                                          │
//! │                                      ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                    CHALLENGE-RESPONSE (FISHERMAN)                          │ │
//! │  │                                                                            │ │
//! │  │   Prover Submits ──► Challenger Disputes ──► Committee Re-runs            │ │
//! │  │         │                    │                     │                       │ │
//! │  │         ▼                    ▼                     ▼                       │ │
//! │  │   Result Locked        Evidence Hash         Majority Vote                │ │
//! │  │                                                    │                       │ │
//! │  │                              ┌─────────────────────┼─────────────────────┐ │ │
//! │  │                              ▼                     ▼                     │ │
//! │  │                      Prover Wrong          Challenger Wrong              │ │
//! │  │                      → 100% Slash          → 20% Spam Penalty            │ │
//! │  │                      → 50% to Challenger   → Continue                    │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                      │                                          │
//! │                                      ▼                                          │
//! │  ┌────────────────────────────────────────────────────────────────────────────┐ │
//! │  │                    ATTESTATION VERIFICATION                                │ │
//! │  │                                                                            │ │
//! │  │   Epoch Start ──► Sample 5% Nodes ──► Challenge Attestation              │ │
//! │  │        │                │                    │                             │ │
//! │  │        ▼                ▼                    ▼                             │ │
//! │  │   Reset Counters   Select Targets      Verify Quote                       │ │
//! │  │                                              │                             │ │
//! │  │                         ┌────────────────────┼────────────────────┐        │ │
//! │  │                         ▼                    ▼                    │        │ │
//! │  │                    Valid Quote         Invalid/Missing            │        │ │
//! │  │                    → Continue          → Tier 3 Slash             │        │ │
//! │  │                                                                            │ │
//! │  └────────────────────────────────────────────────────────────────────────────┘ │
//! │                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Threat Model
//!
//! The slashing engine defends against:
//! - **Fake Proofs**: Claiming AI work was done when it wasn't
//! - **Hardware Spoofing**: Pretending to be an SGX/Nitro enclave
//! - **Result Copying**: Stealing results from other provers
//! - **Double Signing**: Equivocating in consensus
//!
//! ## Author
//!
//! Aethelred Team - Enterprise Security Module
//!
//! ## License
//!
//! Apache-2.0

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::bank::Bank;
use super::error::{Result, SystemContractError};
use super::events::SlashingEvent;
use super::types::{Address, Hash, JobId, TeeAttestation, TeeType, TokenAmount};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum attestation age (24 hours)
pub const MAX_ATTESTATION_AGE_SECS: u64 = 24 * 60 * 60;

/// Attestation challenge interval (4 hours)
pub const ATTESTATION_CHALLENGE_INTERVAL_SECS: u64 = 4 * 60 * 60;

/// Percentage of nodes challenged per epoch
pub const ATTESTATION_CHALLENGE_SAMPLE_PERCENT: u8 = 5;

/// Challenge response window (10 minutes)
pub const CHALLENGE_RESPONSE_WINDOW_SECS: u64 = 10 * 60;

/// Committee size for result re-verification
pub const VERIFICATION_COMMITTEE_SIZE: usize = 3;

/// Minimum committee agreement threshold (2/3)
pub const COMMITTEE_AGREEMENT_THRESHOLD: f64 = 0.67;

/// Tombstone duration (effectively permanent - 100 years)
pub const TOMBSTONE_DURATION_SECS: u64 = 100 * 365 * 24 * 60 * 60;

/// Tier 2 ban duration (30 days)
pub const TIER2_BAN_DURATION_SECS: u64 = 30 * 24 * 60 * 60;

/// Tier 3 suspension duration (24 hours)
pub const TIER3_SUSPENSION_DURATION_SECS: u64 = 24 * 60 * 60;

/// Challenger reward percentage (50% of slashed stake)
pub const CHALLENGER_REWARD_PERCENT: u8 = 50;

/// Spam challenge penalty percentage (20%)
pub const SPAM_CHALLENGE_PENALTY_PERCENT: u8 = 20;

// =============================================================================
// OFFENSE TYPES & SEVERITY
// =============================================================================

/// Offense severity tier with specific penalties
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum OffenseSeverity {
    /// Tier 3: Performance issues (5% slash, 24h suspension)
    Performance = 1,

    /// Tier 2: Malicious behavior (50% slash, 30 day ban)
    Malicious = 2,

    /// Tier 1: Critical fraud (100% slash, permanent tombstone)
    Critical = 3,
}

impl OffenseSeverity {
    /// Get the slash percentage for this severity level
    pub fn slash_percent(&self) -> u8 {
        match self {
            Self::Performance => 5,
            Self::Malicious => 50,
            Self::Critical => 100,
        }
    }

    /// Get the ban duration for this severity level
    pub fn ban_duration(&self) -> Duration {
        match self {
            Self::Performance => Duration::from_secs(TIER3_SUSPENSION_DURATION_SECS),
            Self::Malicious => Duration::from_secs(TIER2_BAN_DURATION_SECS),
            Self::Critical => Duration::from_secs(TOMBSTONE_DURATION_SECS),
        }
    }

    /// Whether this offense results in permanent ejection
    pub fn is_tombstone(&self) -> bool {
        matches!(self, Self::Critical)
    }
}

/// Specific offense types categorized by severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OffenseType {
    // =========================================================================
    // TIER 1 - CRITICAL (100% slash, tombstone)
    // =========================================================================
    /// Submitted a cryptographically invalid zk-proof
    InvalidZkProof,

    /// Forged or tampered TEE attestation signature
    ForgedTeeSignature,

    /// Hardware spoofing - pretending to be a different TEE type
    HardwareSpoofing,

    /// Submitted computation result with fabricated proof
    FabricatedResult,

    /// Attempted to manipulate the random committee selection
    CommitteeManipulation,

    // =========================================================================
    // TIER 2 - MALICIOUS (50% slash, 30 day ban)
    // =========================================================================
    /// Signed two different blocks at the same height
    DoubleSign,

    /// Signed conflicting vote messages in consensus
    Equivocation,

    /// Attempted to vote on same proposal multiple times
    VoteTampering,

    /// Collusion with other validators detected
    CollusionDetected,

    /// Submitting results that were copied from another prover
    ResultPlagiarism,

    // =========================================================================
    // TIER 3 - PERFORMANCE (5% slash, 24h suspension)
    // =========================================================================
    /// Failed to deliver computation result within SLA timeout
    SlaTimeout,

    /// Delivered result late but within grace period
    LateDelivery,

    /// Submitted partial or incomplete results
    IncompleteResult,

    /// Failed to respond to attestation challenge
    AttestationChallengeFailure,

    /// Excessive job abandonment rate
    JobAbandonment,

    /// Reliability score dropped below minimum threshold
    LowReliability,
}

impl OffenseType {
    /// Get the severity tier for this offense
    pub fn severity(&self) -> OffenseSeverity {
        match self {
            // Tier 1 - Critical
            Self::InvalidZkProof
            | Self::ForgedTeeSignature
            | Self::HardwareSpoofing
            | Self::FabricatedResult
            | Self::CommitteeManipulation => OffenseSeverity::Critical,

            // Tier 2 - Malicious
            Self::DoubleSign
            | Self::Equivocation
            | Self::VoteTampering
            | Self::CollusionDetected
            | Self::ResultPlagiarism => OffenseSeverity::Malicious,

            // Tier 3 - Performance
            Self::SlaTimeout
            | Self::LateDelivery
            | Self::IncompleteResult
            | Self::AttestationChallengeFailure
            | Self::JobAbandonment
            | Self::LowReliability => OffenseSeverity::Performance,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidZkProof => "Submitted cryptographically invalid zero-knowledge proof",
            Self::ForgedTeeSignature => "Forged or tampered TEE attestation signature",
            Self::HardwareSpoofing => "Hardware spoofing - misrepresented TEE enclave type",
            Self::FabricatedResult => "Fabricated computation result without valid proof",
            Self::CommitteeManipulation => "Attempted manipulation of verification committee",
            Self::DoubleSign => "Double-signed conflicting blocks at same height",
            Self::Equivocation => "Signed conflicting consensus messages",
            Self::VoteTampering => "Attempted to manipulate consensus votes",
            Self::CollusionDetected => "Detected collusion with other network participants",
            Self::ResultPlagiarism => "Copied computation results from another prover",
            Self::SlaTimeout => "Failed to deliver result within SLA timeout",
            Self::LateDelivery => "Delivered result after deadline but within grace",
            Self::IncompleteResult => "Submitted incomplete or partial results",
            Self::AttestationChallengeFailure => "Failed attestation verification challenge",
            Self::JobAbandonment => "Excessive job abandonment rate",
            Self::LowReliability => "Reliability score below minimum threshold",
        }
    }
}

// =============================================================================
// SLASHING CONDITION & EVIDENCE
// =============================================================================

/// Complete slashing condition with evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingCondition {
    /// Address of the offender
    pub offender: Address,

    /// Type of offense committed
    pub offense_type: OffenseType,

    /// Block height where offense occurred
    pub block_height: u64,

    /// Timestamp of the offense
    pub timestamp: u64,

    /// Cryptographic evidence of the offense
    pub evidence: SlashingEvidence,

    /// Optional challenger who reported the offense
    pub reporter: Option<Address>,

    /// Hash of the job if applicable
    pub job_id: Option<JobId>,
}

/// Cryptographic evidence for different offense types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Evidence for double signing - two conflicting signed headers
    DoubleSign {
        /// First signed header
        header_a: SignedBlockHeader,
        /// Second conflicting header
        header_b: SignedBlockHeader,
    },

    /// Evidence for equivocation - conflicting vote messages
    Equivocation {
        /// First vote
        vote_a: SignedVote,
        /// Conflicting vote
        vote_b: SignedVote,
    },

    /// Evidence for invalid proof
    InvalidProof {
        /// The invalid proof bytes
        proof_bytes: Vec<u8>,
        /// Expected public inputs hash
        expected_inputs_hash: Hash,
        /// Actual public inputs hash
        actual_inputs_hash: Hash,
        /// Verification failure reason
        failure_reason: String,
    },

    /// Evidence for forged TEE signature
    ForgedTeeAttestation {
        /// The forged attestation
        attestation: TeeAttestation,
        /// Reason for invalidity
        invalidity_reason: String,
    },

    /// Evidence for hardware spoofing
    HardwareSpoofing {
        /// Claimed TEE type
        claimed_type: TeeType,
        /// Detected actual type
        detected_type: Option<TeeType>,
        /// Detection method
        detection_method: String,
    },

    /// Evidence for SLA violation
    SlaViolation {
        /// Job ID
        job_id: JobId,
        /// SLA deadline timestamp
        deadline: u64,
        /// Actual delivery timestamp (if any)
        delivery_time: Option<u64>,
        /// Expected result hash
        expected_result_hash: Option<Hash>,
    },

    /// Evidence for result plagiarism
    ResultPlagiarism {
        /// Original prover's submission
        original_submission: ProofSubmission,
        /// Plagiarized submission
        copied_submission: ProofSubmission,
        /// Similarity score (0-100)
        similarity_score: u8,
    },

    /// Evidence from committee re-verification
    CommitteeVerification {
        /// Original submitted result
        original_result: Vec<u8>,
        /// Committee members
        committee: Vec<Address>,
        /// Committee votes (true = agrees with challenge)
        votes: Vec<bool>,
        /// Recomputed results from committee
        committee_results: Vec<Vec<u8>>,
    },

    /// Evidence for attestation challenge failure
    AttestationFailure {
        /// Challenge ID
        challenge_id: Hash,
        /// Challenge timestamp
        challenge_time: u64,
        /// Response deadline
        response_deadline: u64,
        /// Whether any response was received
        response_received: bool,
    },

    /// Generic evidence (raw bytes with description)
    Generic {
        /// Evidence description
        description: String,
        /// Raw evidence bytes
        data: Vec<u8>,
    },
}

/// Signed block header for double-sign evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedBlockHeader {
    pub height: u64,
    pub round: u32,
    pub block_hash: Hash,
    pub timestamp: u64,
    pub proposer: Address,
    pub signature: Vec<u8>,
}

/// Signed vote for equivocation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVote {
    pub height: u64,
    pub round: u32,
    pub vote_type: VoteType,
    pub block_hash: Hash,
    pub voter: Address,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

/// Vote type in consensus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
}

/// Proof submission for plagiarism detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    pub job_id: JobId,
    pub prover: Address,
    pub result_hash: Hash,
    pub proof_hash: Hash,
    pub submission_time: u64,
    pub block_height: u64,
}

// =============================================================================
// SLASHING RESULT
// =============================================================================

/// Result of executing a slash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingResult {
    /// Address that was slashed
    pub slashed_address: Address,

    /// Amount of stake burned
    pub burn_amount: TokenAmount,

    /// Amount rewarded to reporter (if any)
    pub reporter_reward: TokenAmount,

    /// New ban expiry timestamp
    pub ban_until: u64,

    /// Whether address is tombstoned (permanently banned)
    pub tombstoned: bool,

    /// Events emitted
    pub events: Vec<SlashingEvent>,
}

// =============================================================================
// CHALLENGE STATE
// =============================================================================

/// State of an active challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: Hash,

    /// Job being challenged
    pub job_id: JobId,

    /// Original prover
    pub prover: Address,

    /// Challenger address
    pub challenger: Address,

    /// Original submitted result hash
    pub original_result_hash: Hash,

    /// Challenge creation time
    pub created_at: u64,

    /// Challenge expiry time
    pub expires_at: u64,

    /// Current state
    pub state: ChallengeState,

    /// Verification committee members
    pub committee: Vec<Address>,

    /// Committee votes received
    pub committee_votes: HashMap<Address, ChallengeVote>,

    /// Stake locked from challenger
    pub challenger_stake_locked: TokenAmount,
}

/// State of a challenge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeState {
    /// Awaiting committee formation
    Pending,
    /// Committee is re-running the computation
    InProgress,
    /// Committee has voted, awaiting finalization
    Voting,
    /// Challenge resolved - prover was wrong
    ResolvedProverFault,
    /// Challenge resolved - challenger was wrong (spam)
    ResolvedChallengerFault,
    /// Challenge expired without resolution
    Expired,
}

/// Vote from a committee member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeVote {
    pub voter: Address,
    pub agrees_with_challenge: bool,
    pub computed_result_hash: Hash,
    pub vote_time: u64,
    pub signature: Vec<u8>,
}

// =============================================================================
// ATTESTATION CHALLENGE
// =============================================================================

/// Attestation verification challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChallenge {
    /// Challenge ID
    pub id: Hash,

    /// Target node address
    pub target: Address,

    /// Challenge issued at
    pub issued_at: u64,

    /// Response deadline
    pub deadline: u64,

    /// Whether response was received
    pub response_received: bool,

    /// Attestation if received
    pub attestation: Option<TeeAttestation>,

    /// Verification result
    pub verified: Option<bool>,
}

// =============================================================================
// RELIABILITY TRACKING
// =============================================================================

/// Reliability metrics for a node
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReliabilityMetrics {
    /// Total jobs assigned
    pub jobs_assigned: u64,

    /// Jobs completed successfully
    pub jobs_completed: u64,

    /// Jobs failed or abandoned
    pub jobs_failed: u64,

    /// Jobs delivered late
    pub jobs_late: u64,

    /// Total SLA violations
    pub sla_violations: u64,

    /// Last reliability score calculation
    pub last_score: u16, // basis points (0-10000)

    /// Score calculation timestamp
    pub score_timestamp: u64,

    /// Rolling window of recent job outcomes (true = success)
    pub recent_outcomes: VecDeque<bool>,
}

impl ReliabilityMetrics {
    /// Maximum outcomes to track in rolling window
    const ROLLING_WINDOW_SIZE: usize = 100;

    /// Minimum reliability score (basis points)
    const MIN_RELIABILITY_BPS: u16 = 9000; // 90%

    /// Calculate current reliability score (basis points)
    pub fn calculate_score(&mut self, current_time: u64) -> u16 {
        if self.jobs_assigned == 0 {
            return 10000; // Perfect score for new nodes
        }

        // Use rolling window if enough data
        if self.recent_outcomes.len() >= 10 {
            let successes = self.recent_outcomes.iter().filter(|&&x| x).count();
            let score = (successes * 10000 / self.recent_outcomes.len()) as u16;
            self.last_score = score;
            self.score_timestamp = current_time;
            return score;
        }

        // Fall back to all-time stats
        let score = (self.jobs_completed * 10000 / self.jobs_assigned) as u16;
        self.last_score = score;
        self.score_timestamp = current_time;
        score
    }

    /// Record a job outcome
    pub fn record_outcome(&mut self, success: bool) {
        self.jobs_assigned += 1;

        if success {
            self.jobs_completed += 1;
        } else {
            self.jobs_failed += 1;
        }

        // Update rolling window
        self.recent_outcomes.push_back(success);
        while self.recent_outcomes.len() > Self::ROLLING_WINDOW_SIZE {
            self.recent_outcomes.pop_front();
        }
    }

    /// Check if reliability is below minimum threshold
    pub fn is_below_threshold(&self) -> bool {
        self.last_score < Self::MIN_RELIABILITY_BPS
    }
}

// =============================================================================
// BAN RECORD
// =============================================================================

/// Record of a banned address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    /// Banned address
    pub address: Address,

    /// Ban start time
    pub banned_at: u64,

    /// Ban expiry time (u64::MAX for tombstone)
    pub banned_until: u64,

    /// Offense that caused the ban
    pub offense: OffenseType,

    /// Number of offenses (for repeat offenders)
    pub offense_count: u32,

    /// Whether this is a permanent tombstone
    pub tombstoned: bool,

    /// IP addresses associated (for network-level ban)
    pub associated_ips: HashSet<String>,
}

impl BanRecord {
    /// Check if ban is still active
    pub fn is_active(&self, current_time: u64) -> bool {
        self.tombstoned || current_time < self.banned_until
    }
}

// =============================================================================
// SLASHING MANAGER
// =============================================================================

/// Configuration for the slashing manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Enable slashing (can be disabled for testing)
    pub enabled: bool,

    /// Tier 1 (Critical) slash percentage
    pub tier1_slash_percent: u8,

    /// Tier 2 (Malicious) slash percentage
    pub tier2_slash_percent: u8,

    /// Tier 3 (Performance) slash percentage
    pub tier3_slash_percent: u8,

    /// Challenger reward percentage
    pub challenger_reward_percent: u8,

    /// Spam challenge penalty percentage
    pub spam_penalty_percent: u8,

    /// Challenge response window (seconds)
    pub challenge_window_secs: u64,

    /// Verification committee size
    pub committee_size: usize,

    /// Committee agreement threshold (0.0-1.0)
    pub committee_threshold: f64,

    /// Attestation max age (seconds)
    pub attestation_max_age_secs: u64,

    /// Attestation challenge interval (seconds)
    pub attestation_challenge_interval_secs: u64,

    /// Percentage of nodes to challenge per epoch
    pub attestation_sample_percent: u8,

    /// Minimum reliability score (basis points)
    pub min_reliability_bps: u16,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tier1_slash_percent: 100,
            tier2_slash_percent: 50,
            tier3_slash_percent: 5,
            challenger_reward_percent: CHALLENGER_REWARD_PERCENT,
            spam_penalty_percent: SPAM_CHALLENGE_PENALTY_PERCENT,
            challenge_window_secs: CHALLENGE_RESPONSE_WINDOW_SECS,
            committee_size: VERIFICATION_COMMITTEE_SIZE,
            committee_threshold: COMMITTEE_AGREEMENT_THRESHOLD,
            attestation_max_age_secs: MAX_ATTESTATION_AGE_SECS,
            attestation_challenge_interval_secs: ATTESTATION_CHALLENGE_INTERVAL_SECS,
            attestation_sample_percent: ATTESTATION_CHALLENGE_SAMPLE_PERCENT,
            min_reliability_bps: ReliabilityMetrics::MIN_RELIABILITY_BPS,
        }
    }
}

impl SlashingConfig {
    /// Production mainnet configuration
    pub fn mainnet() -> Self {
        Self::default()
    }

    /// Testnet configuration (reduced penalties)
    pub fn testnet() -> Self {
        Self {
            tier1_slash_percent: 50,
            tier2_slash_percent: 25,
            tier3_slash_percent: 2,
            challenge_window_secs: 5 * 60, // 5 minutes
            ..Self::default()
        }
    }

    /// DevNet configuration (minimal penalties)
    pub fn devnet() -> Self {
        Self {
            enabled: false, // Disabled for development
            tier1_slash_percent: 10,
            tier2_slash_percent: 5,
            tier3_slash_percent: 1,
            challenge_window_secs: 60, // 1 minute
            attestation_challenge_interval_secs: 60,
            ..Self::default()
        }
    }

    /// Get slash percentage for severity
    pub fn slash_percent_for_severity(&self, severity: OffenseSeverity) -> u8 {
        match severity {
            OffenseSeverity::Critical => self.tier1_slash_percent,
            OffenseSeverity::Malicious => self.tier2_slash_percent,
            OffenseSeverity::Performance => self.tier3_slash_percent,
        }
    }
}

/// The Slashing Manager - core security enforcement
pub struct SlashingManager {
    /// Configuration
    config: SlashingConfig,

    /// Reference to the bank for token operations
    bank: std::sync::Arc<RwLock<Bank>>,

    /// Active challenges
    challenges: HashMap<Hash, Challenge>,

    /// Active attestation challenges
    attestation_challenges: HashMap<Hash, AttestationChallenge>,

    /// Ban records by address
    bans: HashMap<Address, BanRecord>,

    /// Tombstoned addresses (permanent)
    tombstones: HashSet<Address>,

    /// Reliability metrics by address
    reliability: HashMap<Address, ReliabilityMetrics>,

    /// Offense history by address
    offense_history: HashMap<Address, Vec<SlashingCondition>>,

    /// Total slashed amount (for statistics)
    total_slashed: TokenAmount,

    /// Total burned amount
    total_burned: TokenAmount,

    /// Last attestation challenge epoch
    last_attestation_epoch: u64,

    /// Pending slash queue (for batched execution)
    pending_slashes: VecDeque<SlashingCondition>,

    /// Event log
    events: Vec<SlashingEvent>,
}

impl SlashingManager {
    /// Create new slashing manager
    pub fn new(config: SlashingConfig, bank: std::sync::Arc<RwLock<Bank>>) -> Self {
        Self {
            config,
            bank,
            challenges: HashMap::new(),
            attestation_challenges: HashMap::new(),
            bans: HashMap::new(),
            tombstones: HashSet::new(),
            reliability: HashMap::new(),
            offense_history: HashMap::new(),
            total_slashed: 0,
            total_burned: 0,
            last_attestation_epoch: 0,
            pending_slashes: VecDeque::new(),
            events: Vec::new(),
        }
    }

    // =========================================================================
    // MAIN SLASHING EXECUTION
    // =========================================================================

    /// Execute a slash based on a slashing condition
    pub fn execute_slash(&mut self, condition: SlashingCondition) -> Result<SlashingResult> {
        if !self.config.enabled {
            return Err(SystemContractError::Slashing("Slashing is disabled".into()));
        }

        // Check if already tombstoned
        if self.tombstones.contains(&condition.offender) {
            return Err(SystemContractError::Slashing(
                "Address is already tombstoned".into(),
            ));
        }

        let severity = condition.offense_type.severity();
        let slash_percent = self.config.slash_percent_for_severity(severity);

        // Get offender's stake
        let stake = self.get_stake(&condition.offender)?;

        if stake == 0 {
            return Err(SystemContractError::Slashing(
                "Offender has no stake".into(),
            ));
        }

        // Calculate slash amount
        let slash_amount = (stake * slash_percent as u128) / 100;

        // Calculate reporter reward (if applicable)
        let reporter_reward = if let Some(reporter) = &condition.reporter {
            let reward = (slash_amount * self.config.challenger_reward_percent as u128) / 100;
            // Transfer reward to reporter
            self.bank
                .write()
                .transfer(condition.offender, *reporter, reward)?;
            reward
        } else {
            0
        };

        // Burn the remainder
        let burn_amount = slash_amount - reporter_reward;
        self.bank.write().burn(condition.offender, burn_amount)?;

        // Update statistics
        self.total_slashed += slash_amount;
        self.total_burned += burn_amount;

        // Determine ban duration
        let current_time = condition.timestamp;
        let ban_duration = severity.ban_duration();
        let ban_until = if severity.is_tombstone() {
            u64::MAX
        } else {
            current_time + ban_duration.as_secs()
        };

        // Record ban
        let tombstoned = severity.is_tombstone();
        self.record_ban(
            &condition.offender,
            current_time,
            ban_until,
            condition.offense_type,
            tombstoned,
        );

        // Record offense in history
        self.offense_history
            .entry(condition.offender)
            .or_default()
            .push(condition.clone());

        // Emit event
        let event = SlashingEvent::Slashed {
            offender: condition.offender,
            offense_type: condition.offense_type,
            slash_amount,
            burn_amount,
            reporter_reward,
            reporter: condition.reporter,
            ban_until,
            tombstoned,
            evidence_hash: self.hash_evidence(&condition.evidence),
        };
        self.events.push(event.clone());

        Ok(SlashingResult {
            slashed_address: condition.offender,
            burn_amount,
            reporter_reward,
            ban_until,
            tombstoned,
            events: vec![event],
        })
    }

    /// Queue a slash for batched execution
    pub fn queue_slash(&mut self, condition: SlashingCondition) {
        self.pending_slashes.push_back(condition);
    }

    /// Process all queued slashes
    pub fn process_pending_slashes(&mut self) -> Vec<Result<SlashingResult>> {
        let mut results = Vec::new();

        while let Some(condition) = self.pending_slashes.pop_front() {
            results.push(self.execute_slash(condition));
        }

        results
    }

    // =========================================================================
    // CHALLENGE-RESPONSE MECHANISM (FISHERMAN)
    // =========================================================================

    /// Submit a challenge against a prover's result
    pub fn submit_challenge(
        &mut self,
        challenger: Address,
        job_id: JobId,
        prover: Address,
        original_result_hash: Hash,
        challenger_stake: TokenAmount,
        current_time: u64,
        available_committee: &[Address],
    ) -> Result<Hash> {
        // Validate challenger has enough stake
        let challenger_actual_stake = self.get_stake(&challenger)?;
        if challenger_actual_stake < challenger_stake {
            return Err(SystemContractError::Slashing(
                "Challenger has insufficient stake".into(),
            ));
        }

        // Lock challenger's stake
        self.bank.write().lock(&challenger, challenger_stake)?;

        // Generate challenge ID
        let challenge_id = self.generate_challenge_id(&job_id, &challenger, current_time);

        // Select verification committee
        let committee = self.select_committee(available_committee, &challenge_id)?;

        let challenge = Challenge {
            id: challenge_id,
            job_id,
            prover,
            challenger,
            original_result_hash,
            created_at: current_time,
            expires_at: current_time + self.config.challenge_window_secs,
            state: ChallengeState::Pending,
            committee: committee.clone(),
            committee_votes: HashMap::new(),
            challenger_stake_locked: challenger_stake,
        };

        self.challenges.insert(challenge_id, challenge);

        // Emit event
        self.events.push(SlashingEvent::ChallengeSubmitted {
            challenge_id,
            challenger,
            prover,
            job_id,
            committee,
        });

        Ok(challenge_id)
    }

    /// Submit a committee member's vote on a challenge
    pub fn submit_committee_vote(
        &mut self,
        challenge_id: Hash,
        voter: Address,
        agrees_with_challenge: bool,
        computed_result_hash: Hash,
        signature: Vec<u8>,
        current_time: u64,
    ) -> Result<()> {
        let challenge = self
            .challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| SystemContractError::Slashing("Challenge not found".into()))?;

        // Verify voter is in committee
        if !challenge.committee.contains(&voter) {
            return Err(SystemContractError::Slashing(
                "Voter is not in committee".into(),
            ));
        }

        // Verify not already voted
        if challenge.committee_votes.contains_key(&voter) {
            return Err(SystemContractError::Slashing(
                "Voter has already voted".into(),
            ));
        }

        // Record vote
        challenge.committee_votes.insert(
            voter,
            ChallengeVote {
                voter,
                agrees_with_challenge,
                computed_result_hash,
                vote_time: current_time,
                signature,
            },
        );

        // Update state if enough votes
        if challenge.committee_votes.len() >= challenge.committee.len() {
            challenge.state = ChallengeState::Voting;
        }

        Ok(())
    }

    /// Finalize a challenge after committee voting
    pub fn finalize_challenge(
        &mut self,
        challenge_id: Hash,
        current_time: u64,
    ) -> Result<SlashingResult> {
        let challenge = self
            .challenges
            .remove(&challenge_id)
            .ok_or_else(|| SystemContractError::Slashing("Challenge not found".into()))?;

        // Check if expired
        if current_time > challenge.expires_at {
            // Return challenger stake
            self.bank
                .write()
                .unlock(&challenge.challenger, challenge.challenger_stake_locked)?;
            return Err(SystemContractError::Slashing("Challenge expired".into()));
        }

        // Count votes
        let total_votes = challenge.committee_votes.len();
        let votes_for_challenge = challenge
            .committee_votes
            .values()
            .filter(|v| v.agrees_with_challenge)
            .count();

        let challenge_succeeds =
            (votes_for_challenge as f64 / total_votes as f64) >= self.config.committee_threshold;

        if challenge_succeeds {
            // Prover was wrong - slash them
            let evidence = SlashingEvidence::CommitteeVerification {
                original_result: vec![], // Would contain actual result
                committee: challenge.committee.clone(),
                votes: challenge
                    .committee_votes
                    .values()
                    .map(|v| v.agrees_with_challenge)
                    .collect(),
                committee_results: challenge
                    .committee_votes
                    .values()
                    .map(|v| v.computed_result_hash.to_vec())
                    .collect(),
            };

            let condition = SlashingCondition {
                offender: challenge.prover,
                offense_type: OffenseType::FabricatedResult,
                block_height: 0, // Would be set properly
                timestamp: current_time,
                evidence,
                reporter: Some(challenge.challenger),
                job_id: Some(challenge.job_id),
            };

            // Unlock challenger stake
            self.bank
                .write()
                .unlock(&challenge.challenger, challenge.challenger_stake_locked)?;

            self.execute_slash(condition)
        } else {
            // Challenger was wrong - spam penalty
            let spam_penalty = (challenge.challenger_stake_locked
                * self.config.spam_penalty_percent as u128)
                / 100;

            // Burn spam penalty from locked stake
            self.bank
                .write()
                .unlock(&challenge.challenger, challenge.challenger_stake_locked)?;
            self.bank.write().burn(challenge.challenger, spam_penalty)?;

            self.events.push(SlashingEvent::SpamChallengePenalty {
                challenger: challenge.challenger,
                penalty_amount: spam_penalty,
                challenge_id,
            });

            Ok(SlashingResult {
                slashed_address: challenge.challenger,
                burn_amount: spam_penalty,
                reporter_reward: 0,
                ban_until: 0,
                tombstoned: false,
                events: vec![],
            })
        }
    }

    // =========================================================================
    // ATTESTATION VERIFICATION
    // =========================================================================

    /// Issue attestation challenges to sampled nodes
    pub fn issue_attestation_challenges(
        &mut self,
        eligible_nodes: &[Address],
        current_time: u64,
        randomness: &[u8],
    ) -> Vec<AttestationChallenge> {
        // Check if enough time has passed since last challenge round
        if current_time
            < self.last_attestation_epoch + self.config.attestation_challenge_interval_secs
        {
            return vec![];
        }

        self.last_attestation_epoch = current_time;

        // Sample nodes
        let sample_count =
            (eligible_nodes.len() * self.config.attestation_sample_percent as usize) / 100;
        let sample_count = sample_count.max(1).min(eligible_nodes.len());

        let selected = self.select_random_nodes(eligible_nodes, sample_count, randomness);

        let mut challenges = Vec::new();

        for target in selected {
            let challenge_id =
                self.generate_attestation_challenge_id(&target, current_time, randomness);

            let challenge = AttestationChallenge {
                id: challenge_id,
                target,
                issued_at: current_time,
                deadline: current_time + self.config.challenge_window_secs,
                response_received: false,
                attestation: None,
                verified: None,
            };

            self.attestation_challenges
                .insert(challenge_id, challenge.clone());

            self.events.push(SlashingEvent::AttestationChallengeIssued {
                challenge_id,
                target,
                deadline: current_time + self.config.challenge_window_secs,
            });

            challenges.push(challenge);
        }

        challenges
    }

    /// Submit attestation response
    pub fn submit_attestation_response(
        &mut self,
        challenge_id: Hash,
        attestation: TeeAttestation,
        current_time: u64,
    ) -> Result<bool> {
        let deadline = self
            .attestation_challenges
            .get(&challenge_id)
            .ok_or_else(|| {
                SystemContractError::Slashing("Attestation challenge not found".into())
            })?;

        // Check deadline
        if current_time > deadline.deadline {
            return Err(SystemContractError::Slashing(
                "Attestation response too late".into(),
            ));
        }

        // Verify attestation
        let verified = self.verify_attestation(&attestation, current_time)?;

        let challenge = self
            .attestation_challenges
            .get_mut(&challenge_id)
            .ok_or_else(|| {
                SystemContractError::Slashing("Attestation challenge not found".into())
            })?;
        challenge.response_received = true;
        challenge.attestation = Some(attestation);
        challenge.verified = Some(verified);

        Ok(verified)
    }

    /// Process expired attestation challenges
    pub fn process_expired_attestation_challenges(
        &mut self,
        current_time: u64,
    ) -> Vec<SlashingCondition> {
        let mut conditions = Vec::new();

        let expired: Vec<_> = self
            .attestation_challenges
            .iter()
            .filter(|(_, c)| current_time > c.deadline && !c.response_received)
            .map(|(id, c)| (*id, c.target))
            .collect();

        for (id, target) in expired {
            if let Some(challenge) = self.attestation_challenges.remove(&id) {
                conditions.push(SlashingCondition {
                    offender: target,
                    offense_type: OffenseType::AttestationChallengeFailure,
                    block_height: 0,
                    timestamp: current_time,
                    evidence: SlashingEvidence::AttestationFailure {
                        challenge_id: id,
                        challenge_time: challenge.issued_at,
                        response_deadline: challenge.deadline,
                        response_received: false,
                    },
                    reporter: None,
                    job_id: None,
                });
            }
        }

        conditions
    }

    /// Verify a TEE attestation
    fn verify_attestation(&self, attestation: &TeeAttestation, current_time: u64) -> Result<bool> {
        // Check attestation age
        let age = current_time.saturating_sub(attestation.timestamp);
        if age > self.config.attestation_max_age_secs {
            return Ok(false);
        }

        // Verify attestation based on type
        match attestation.tee_type {
            TeeType::IntelSgx => {
                // Placeholder validation: ensure payload and measurement are present.
                Ok(!attestation.attestation.is_empty() && attestation.measurement != [0u8; 32])
            }
            TeeType::AwsNitro => Ok(!attestation.attestation.is_empty()),
            TeeType::AmdSev => Ok(!attestation.attestation.is_empty()),
        }
    }

    // =========================================================================
    // RELIABILITY TRACKING
    // =========================================================================

    /// Record a job outcome for reliability tracking
    pub fn record_job_outcome(&mut self, node: &Address, success: bool, current_time: u64) {
        let metrics = self.reliability.entry(*node).or_default();
        metrics.record_outcome(success);

        // Check if reliability dropped below threshold
        let score = metrics.calculate_score(current_time);

        if metrics.is_below_threshold() {
            // Queue a slash for low reliability
            self.queue_slash(SlashingCondition {
                offender: *node,
                offense_type: OffenseType::LowReliability,
                block_height: 0,
                timestamp: current_time,
                evidence: SlashingEvidence::Generic {
                    description: format!(
                        "Reliability score {} below threshold {}",
                        score, self.config.min_reliability_bps
                    ),
                    data: vec![],
                },
                reporter: None,
                job_id: None,
            });
        }
    }

    /// Get reliability score for a node
    pub fn get_reliability_score(&self, node: &Address) -> u16 {
        self.reliability
            .get(node)
            .map(|m| m.last_score)
            .unwrap_or(10000) // Perfect score for unknown nodes
    }

    /// Get full reliability metrics for a node
    pub fn get_reliability_metrics(&self, node: &Address) -> Option<&ReliabilityMetrics> {
        self.reliability.get(node)
    }

    // =========================================================================
    // BAN MANAGEMENT
    // =========================================================================

    /// Check if an address is banned
    pub fn is_banned(&self, address: &Address, current_time: u64) -> bool {
        if self.tombstones.contains(address) {
            return true;
        }

        self.bans
            .get(address)
            .map(|ban| ban.is_active(current_time))
            .unwrap_or(false)
    }

    /// Check if an address is tombstoned
    pub fn is_tombstoned(&self, address: &Address) -> bool {
        self.tombstones.contains(address)
    }

    /// Get ban record for an address
    pub fn get_ban_record(&self, address: &Address) -> Option<&BanRecord> {
        self.bans.get(address)
    }

    /// Record a ban
    fn record_ban(
        &mut self,
        address: &Address,
        banned_at: u64,
        banned_until: u64,
        offense: OffenseType,
        tombstoned: bool,
    ) {
        if tombstoned {
            self.tombstones.insert(*address);
        }

        let offense_count = self
            .bans
            .get(address)
            .map(|b| b.offense_count + 1)
            .unwrap_or(1);

        self.bans.insert(
            *address,
            BanRecord {
                address: *address,
                banned_at,
                banned_until,
                offense,
                offense_count,
                tombstoned,
                associated_ips: HashSet::new(),
            },
        );
    }

    // =========================================================================
    // DOUBLE SIGN DETECTION
    // =========================================================================

    /// Verify double sign evidence and create slashing condition
    pub fn verify_double_sign(
        &self,
        header_a: &SignedBlockHeader,
        header_b: &SignedBlockHeader,
    ) -> Result<SlashingCondition> {
        // Verify same height
        if header_a.height != header_b.height {
            return Err(SystemContractError::Slashing(
                "Headers are not at same height".into(),
            ));
        }

        // Verify same round
        if header_a.round != header_b.round {
            return Err(SystemContractError::Slashing(
                "Headers are not in same round".into(),
            ));
        }

        // Verify different block hashes
        if header_a.block_hash == header_b.block_hash {
            return Err(SystemContractError::Slashing(
                "Headers have same block hash - not double sign".into(),
            ));
        }

        // Verify same proposer
        if header_a.proposer != header_b.proposer {
            return Err(SystemContractError::Slashing(
                "Headers from different proposers".into(),
            ));
        }

        // Verify signatures are present and non-empty
        if header_a.signature.is_empty() {
            return Err(SystemContractError::Slashing(
                "Header A has empty signature".into(),
            ));
        }
        if header_b.signature.is_empty() {
            return Err(SystemContractError::Slashing(
                "Header B has empty signature".into(),
            ));
        }

        // Verify signatures are different (same signature = same block, not a double sign)
        if header_a.signature == header_b.signature {
            return Err(SystemContractError::Slashing(
                "Headers have identical signatures - not a valid double sign".into(),
            ));
        }

        // Verify signatures are structurally valid (ed25519 signatures are 64 bytes)
        if header_a.signature.len() != 64 || header_b.signature.len() != 64 {
            return Err(SystemContractError::Slashing(format!(
                "Invalid signature lengths: {} and {} (expected 64)",
                header_a.signature.len(),
                header_b.signature.len()
            )));
        }

        // NOTE: Full ed25519 signature verification against the validator's
        // public key is performed by the consensus layer (CometBFT) before
        // evidence reaches this contract. The system contract validates the
        // structural properties of double-sign evidence. Cryptographic
        // verification of the actual signature bytes requires the validator's
        // public key which is managed by the staking module.

        Ok(SlashingCondition {
            offender: header_a.proposer,
            offense_type: OffenseType::DoubleSign,
            block_height: header_a.height,
            timestamp: header_a.timestamp.max(header_b.timestamp),
            evidence: SlashingEvidence::DoubleSign {
                header_a: header_a.clone(),
                header_b: header_b.clone(),
            },
            reporter: None,
            job_id: None,
        })
    }

    /// Verify equivocation evidence
    pub fn verify_equivocation(
        &self,
        vote_a: &SignedVote,
        vote_b: &SignedVote,
    ) -> Result<SlashingCondition> {
        // Verify same height and round
        if vote_a.height != vote_b.height || vote_a.round != vote_b.round {
            return Err(SystemContractError::Slashing(
                "Votes are not at same height/round".into(),
            ));
        }

        // Verify same vote type
        if vote_a.vote_type != vote_b.vote_type {
            return Err(SystemContractError::Slashing(
                "Votes are different types".into(),
            ));
        }

        // Verify different targets
        if vote_a.block_hash == vote_b.block_hash {
            return Err(SystemContractError::Slashing(
                "Votes for same block - not equivocation".into(),
            ));
        }

        // Verify same voter
        if vote_a.voter != vote_b.voter {
            return Err(SystemContractError::Slashing(
                "Votes from different voters".into(),
            ));
        }

        Ok(SlashingCondition {
            offender: vote_a.voter,
            offense_type: OffenseType::Equivocation,
            block_height: vote_a.height,
            timestamp: vote_a.timestamp.max(vote_b.timestamp),
            evidence: SlashingEvidence::Equivocation {
                vote_a: vote_a.clone(),
                vote_b: vote_b.clone(),
            },
            reporter: None,
            job_id: None,
        })
    }

    // =========================================================================
    // HELPER FUNCTIONS
    // =========================================================================

    /// Get stake for an address
    fn get_stake(&self, address: &Address) -> Result<TokenAmount> {
        // In a real implementation, this would query the staking contract
        // For now, we simulate by querying locked balance
        Ok(self.bank.read().get_locked_balance(address))
    }

    /// Generate deterministic challenge ID
    fn generate_challenge_id(&self, job_id: &JobId, challenger: &Address, timestamp: u64) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(job_id);
        hasher.update(challenger);
        hasher.update(timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Generate attestation challenge ID
    fn generate_attestation_challenge_id(
        &self,
        target: &Address,
        timestamp: u64,
        randomness: &[u8],
    ) -> Hash {
        let mut hasher = Sha256::new();
        hasher.update(b"attestation_challenge");
        hasher.update(target);
        hasher.update(timestamp.to_le_bytes());
        hasher.update(randomness);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Select verification committee from available nodes
    fn select_committee(&self, available: &[Address], challenge_id: &Hash) -> Result<Vec<Address>> {
        if available.len() < self.config.committee_size {
            return Err(SystemContractError::Slashing(format!(
                "Not enough nodes for committee (need {}, have {})",
                self.config.committee_size,
                available.len()
            )));
        }

        // Use challenge_id as randomness for deterministic selection
        let mut selected = Vec::new();
        let mut used_indices = HashSet::new();

        for i in 0..self.config.committee_size {
            let mut hasher = Sha256::new();
            hasher.update(challenge_id);
            hasher.update((i as u32).to_le_bytes());
            let result = hasher.finalize();
            let index =
                u64::from_le_bytes(result[..8].try_into().unwrap()) as usize % available.len();

            // Handle collision
            let mut final_index = index;
            while used_indices.contains(&final_index) {
                final_index = (final_index + 1) % available.len();
            }

            used_indices.insert(final_index);
            selected.push(available[final_index]);
        }

        Ok(selected)
    }

    /// Select random nodes for attestation challenge
    fn select_random_nodes(
        &self,
        available: &[Address],
        count: usize,
        randomness: &[u8],
    ) -> Vec<Address> {
        if available.len() <= count {
            return available.to_vec();
        }

        let mut selected = Vec::new();
        let mut used_indices = HashSet::new();

        for i in 0..count {
            let mut hasher = Sha256::new();
            hasher.update(randomness);
            hasher.update((i as u32).to_le_bytes());
            let result = hasher.finalize();
            let index =
                u64::from_le_bytes(result[..8].try_into().unwrap()) as usize % available.len();

            let mut final_index = index;
            while used_indices.contains(&final_index) {
                final_index = (final_index + 1) % available.len();
            }

            used_indices.insert(final_index);
            selected.push(available[final_index]);
        }

        selected
    }

    /// Hash evidence for logging
    fn hash_evidence(&self, evidence: &SlashingEvidence) -> Hash {
        let serialized = serde_json::to_vec(evidence).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&serialized);
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Drain events
    pub fn drain_events(&mut self) -> Vec<SlashingEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get statistics
    pub fn statistics(&self) -> SlashingStatistics {
        SlashingStatistics {
            total_slashed: self.total_slashed,
            total_burned: self.total_burned,
            active_bans: self.bans.len(),
            tombstones: self.tombstones.len(),
            active_challenges: self.challenges.len(),
            pending_attestation_challenges: self.attestation_challenges.len(),
        }
    }
}

/// Slashing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingStatistics {
    pub total_slashed: TokenAmount,
    pub total_burned: TokenAmount,
    pub active_bans: usize,
    pub tombstones: usize,
    pub active_challenges: usize,
    pub pending_attestation_challenges: usize,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offense_severity_mapping() {
        assert_eq!(
            OffenseType::InvalidZkProof.severity(),
            OffenseSeverity::Critical
        );
        assert_eq!(
            OffenseType::DoubleSign.severity(),
            OffenseSeverity::Malicious
        );
        assert_eq!(
            OffenseType::SlaTimeout.severity(),
            OffenseSeverity::Performance
        );
    }

    #[test]
    fn test_slash_percentages() {
        let config = SlashingConfig::mainnet();
        assert_eq!(
            config.slash_percent_for_severity(OffenseSeverity::Critical),
            100
        );
        assert_eq!(
            config.slash_percent_for_severity(OffenseSeverity::Malicious),
            50
        );
        assert_eq!(
            config.slash_percent_for_severity(OffenseSeverity::Performance),
            5
        );
    }

    #[test]
    fn test_reliability_scoring() {
        let mut metrics = ReliabilityMetrics::default();

        // Record 10 successes
        for _ in 0..10 {
            metrics.record_outcome(true);
        }

        let score = metrics.calculate_score(1000);
        assert_eq!(score, 10000); // 100%

        // Record 2 failures
        for _ in 0..2 {
            metrics.record_outcome(false);
        }

        let score = metrics.calculate_score(2000);
        assert!(score < 10000); // Less than 100%
    }

    #[test]
    fn test_ban_record_expiry() {
        let ban = BanRecord {
            address: [0u8; 32],
            banned_at: 1000,
            banned_until: 2000,
            offense: OffenseType::SlaTimeout,
            offense_count: 1,
            tombstoned: false,
            associated_ips: HashSet::new(),
        };

        assert!(ban.is_active(1500));
        assert!(!ban.is_active(2500));
    }

    #[test]
    fn test_tombstone_permanent() {
        let ban = BanRecord {
            address: [0u8; 32],
            banned_at: 1000,
            banned_until: u64::MAX,
            offense: OffenseType::InvalidZkProof,
            offense_count: 1,
            tombstoned: true,
            associated_ips: HashSet::new(),
        };

        assert!(ban.is_active(u64::MAX - 1));
    }
}
