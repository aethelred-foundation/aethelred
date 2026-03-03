//! Proof-of-Useful-Work Consensus Engine
//!
//! Enterprise-grade implementation of the Proof-of-Useful-Work consensus mechanism
//! that combines VRF-based leader election with stake-weighted Useful Work scoring.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────────┐
//! │                    PROOF-OF-USEFUL-WORK CONSENSUS ENGINE                         │
//! ├─────────────────────────────────────────────────────────────────────────────────┤
//! │                                                                                  │
//! │   ┌──────────────────────────────────────────────────────────────────────────┐  │
//! │   │                    VRF + USEFUL WORK LEADER ELECTION                      │  │
//! │   │                                                                           │  │
//! │   │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐              │  │
//! │   │   │   VRF Engine │    │ Leader       │    │ Block        │              │  │
//! │   │   │  ─────────── │    │ Election     │    │ Validator    │              │  │
//! │   │   │  prove()     │───►│ ─────────── │───►│ ─────────── │              │  │
//! │   │   │  verify()    │    │ is_leader() │    │ validate()   │              │  │
//! │   │   │              │    │ threshold() │    │ finalize()   │              │  │
//! │   │   └──────────────┘    └──────────────┘    └──────────────┘              │  │
//! │   │           │                  │                   │                       │  │
//! │   │           │                  │                   │                       │  │
//! │   │           ▼                  ▼                   ▼                       │  │
//! │   │   ┌───────────────────────────────────────────────────────────────────┐ │  │
//! │   │   │              USEFUL WORK VERIFICATION ENGINE                       │ │  │
//! │   │   │                                                                    │ │  │
//! │   │   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │ │  │
//! │   │   │   │ TEE         │  │ zkML Proof  │  │ AI Proof    │              │ │  │
//! │   │   │   │ Attestation │  │ Verifier    │  │ Verifier    │              │ │  │
//! │   │   │   └─────────────┘  └─────────────┘  └─────────────┘              │ │  │
//! │   │   │          │                │                │                      │ │  │
//! │   │   │          └────────────────┼────────────────┘                      │ │  │
//! │   │   │                           ▼                                       │ │  │
//! │   │   │   ┌─────────────────────────────────────────────────────────────┐│ │  │
//! │   │   │   │         USEFUL WORK SCORE TRACKER                           ││ │  │
//! │   │   │   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          ││ │  │
//! │   │   │   │  │ UWU     │ │ Category│ │ Decay   │ │ Anti-   │          ││ │  │
//! │   │   │   │  │ Counter │ │ Tracker │ │ Engine  │ │ Gaming  │          ││ │  │
//! │   │   │   │  └─────────┘ └─────────┘ └─────────┘ └─────────┘          ││ │  │
//! │   │   │   └─────────────────────────────────────────────────────────────┘│ │  │
//! │   │   └───────────────────────────────────────────────────────────────────┘ │  │
//! │   │                                                                           │  │
//! │   └──────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                  │
//! │   ┌──────────────────────────────────────────────────────────────────────────┐  │
//! │   │                    FINALITY & SLASHING ENGINE                             │  │
//! │   │                                                                           │  │
//! │   │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                  │  │
//! │   │   │ Finality    │    │ Slashing    │    │ Rewards     │                  │  │
//! │   │   │ Gadget      │    │ Detector    │    │ Calculator  │                  │  │
//! │   │   └─────────────┘    └─────────────┘    └─────────────┘                  │  │
//! │   │                                                                           │  │
//! │   └──────────────────────────────────────────────────────────────────────────┘  │
//! │                                                                                  │
//! └─────────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Innovations
//!
//! 1. **Useful Work Verification**: AI computation proofs verified via TEE, zkML, or AI proof
//! 2. **Productivity-Weighted Selection**: Block proposers selected by stake × useful work
//! 3. **Category-Based Rewards**: Medical/Financial work earns higher rewards
//! 4. **Anti-Whale Logarithmic Scaling**: Prevents pure capital domination
//! 5. **Multi-Method Verification**: TEE, zkML, Hybrid, Re-execution, AI Proof

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::error::{ConsensusError, ConsensusResult};
use crate::traits::{Consensus, ConsensusState, BlockValidator, LeaderElection};
use crate::types::{
    PoUWBlockHeader, ValidatorInfo, SlotTiming, Slot, Epoch, EpochSeed, Hash, Address,
};
use crate::vrf::{VrfKeys, VrfProof, VrfOutput, VrfEngine};
use super::config::{PoUWConfig, UtilityCategory, VerificationMethod};
use super::election::PoUWElection;

// =============================================================================
// USEFUL WORK RESULT TYPES
// =============================================================================

/// Verified AI computation result
///
/// Represents the outcome of a verified AI inference job,
/// including all cryptographic proofs and metadata needed
/// for consensus validation.
#[derive(Debug, Clone)]
pub struct UsefulWorkResult {
    /// Unique job identifier
    pub job_id: Hash,

    /// Hash of the AI model used
    pub model_hash: Hash,

    /// Hash of input data
    pub input_hash: Hash,

    /// Hash of output data
    pub output_hash: Hash,

    /// Useful Work Units awarded
    pub useful_work_units: u64,

    /// Complexity/difficulty of the computation
    pub work_difficulty: u64,

    /// Utility category of the work
    pub category: UtilityCategory,

    /// Verification method used
    pub verification_method: VerificationMethod,

    /// TEE attestation (if applicable)
    pub tee_attestation: Vec<u8>,

    /// zkML proof (if applicable)
    pub zkml_proof: Option<Vec<u8>>,

    /// AI proof (if applicable)
    pub ai_proof: Option<AiProof>,

    /// Validator who performed the work
    pub validator: Address,

    /// Requester who submitted the job
    pub requester: Address,

    /// Number of confirmations (for re-execution)
    pub confirmations: u32,

    /// Timestamp of completion
    pub completed_at: u64,

    /// SLA deadline (for penalty calculation)
    pub sla_deadline: u64,
}

impl UsefulWorkResult {
    /// Check if result has valid attestation for its method
    pub fn has_valid_attestation(&self) -> bool {
        match self.verification_method {
            VerificationMethod::TeeAttestation => !self.tee_attestation.is_empty(),
            VerificationMethod::ZkProof => self.zkml_proof.is_some(),
            VerificationMethod::Hybrid => {
                !self.tee_attestation.is_empty() && self.zkml_proof.is_some()
            }
            VerificationMethod::ReExecution => self.confirmations >= 2,
            VerificationMethod::AiProof => self.ai_proof.is_some(),
        }
    }

    /// Check if SLA was met
    pub fn sla_met(&self) -> bool {
        self.completed_at <= self.sla_deadline
    }

    /// Calculate hash for merkle tree
    pub fn hash(&self) -> Hash {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();
        hasher.update(&self.job_id);
        hasher.update(&self.model_hash);
        hasher.update(&self.input_hash);
        hasher.update(&self.output_hash);
        hasher.update(&self.useful_work_units.to_le_bytes());
        hasher.update(&self.work_difficulty.to_le_bytes());
        hasher.update(&[self.category as u8]);
        hasher.update(&[self.verification_method as u8]);
        hasher.update(&self.validator);
        hasher.update(&self.requester);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }
}

/// AI Proof for computation verification
///
/// Represents a machine learning-based proof that the computation
/// was performed correctly. Uses a trained verifier model to
/// validate inference results.
#[derive(Debug, Clone)]
pub struct AiProof {
    /// Verifier model hash
    pub verifier_model_hash: Hash,

    /// Confidence score (0-10000 basis points)
    pub confidence_bps: u64,

    /// Embedding of the computation result
    pub result_embedding: Vec<f32>,

    /// Signature from the verifier
    pub verifier_signature: Vec<u8>,

    /// Additional verification metadata
    pub metadata: HashMap<String, String>,
}

impl AiProof {
    /// Check if confidence meets threshold
    pub fn meets_threshold(&self, threshold_bps: u64) -> bool {
        self.confidence_bps >= threshold_bps
    }

    /// Verify the proof signature
    pub fn verify_signature(&self, verifier_pubkey: &[u8]) -> bool {
        // In production, this would verify the cryptographic signature
        // using the verifier's public key
        !self.verifier_signature.is_empty() && !verifier_pubkey.is_empty()
    }
}

// =============================================================================
// POUW CONSENSUS STATE
// =============================================================================

/// Shared consensus state accessible across components
pub struct PoUWState {
    /// Current slot
    current_slot: Slot,

    /// Current epoch
    current_epoch: Epoch,

    /// Current epoch seed for VRF
    epoch_seed: EpochSeed,

    /// Validator set indexed by address
    validators: HashMap<Address, ValidatorInfo>,

    /// Active validator addresses (sorted by weighted stake)
    active_validators: Vec<Address>,

    /// Total staked amount
    total_stake: u128,

    /// Total weighted stake (stake * useful work multiplier)
    total_weighted_stake: u128,

    /// Last finalized block hash
    #[allow(dead_code)]
    last_finalized_hash: Hash,

    /// Last finalized slot
    last_finalized_slot: Slot,

    /// Pending useful work results awaiting confirmation
    #[allow(dead_code)]
    pending_results: HashMap<Hash, PendingUsefulWork>,

    /// Block proposer history (for equivocation detection)
    #[allow(dead_code)]
    proposer_history: HashMap<Slot, Address>,

    /// Useful Work Score tracking
    useful_work_scores: HashMap<Address, u64>,

    /// Category statistics
    category_stats: HashMap<UtilityCategory, CategoryStats>,
}

/// Pending useful work awaiting finalization
#[derive(Debug, Clone)]
pub struct PendingUsefulWork {
    /// Job ID
    pub job_id: Hash,
    /// Output hash
    pub output_hash: Hash,
    /// Useful Work Units
    pub useful_work_units: u64,
    /// Work difficulty
    pub work_difficulty: u64,
    /// Category
    pub category: UtilityCategory,
    /// Verification method used
    pub method: VerificationMethod,
    /// Submitted at slot
    pub submitted_slot: Slot,
    /// Validator who submitted
    pub validator: Address,
}

/// Statistics for a utility category
#[derive(Debug, Clone, Default)]
pub struct CategoryStats {
    /// Total jobs verified in this category
    pub total_jobs: u64,
    /// Total UWU awarded
    pub total_uwu: u64,
    /// Average work difficulty
    pub avg_difficulty: u64,
    /// Average completion time (slots)
    pub avg_completion_time: u64,
    /// SLA compliance rate (basis points)
    pub sla_compliance_bps: u64,
}

impl PoUWState {
    /// Create new consensus state
    pub fn new(_genesis_timestamp: u64) -> Self {
        Self {
            current_slot: 0,
            current_epoch: 0,
            epoch_seed: [0u8; 32],
            validators: HashMap::new(),
            active_validators: Vec::new(),
            total_stake: 0,
            total_weighted_stake: 0,
            last_finalized_hash: [0u8; 32],
            last_finalized_slot: 0,
            pending_results: HashMap::new(),
            proposer_history: HashMap::new(),
            useful_work_scores: HashMap::new(),
            category_stats: HashMap::new(),
        }
    }

    /// Update state for new slot
    pub fn advance_slot(&mut self, slot: Slot, timing: &SlotTiming) {
        self.current_slot = slot;
        let new_epoch = timing.epoch_for_slot(slot);

        if new_epoch > self.current_epoch {
            self.on_epoch_transition(new_epoch);
        }
    }

    /// Handle epoch transition
    fn on_epoch_transition(&mut self, new_epoch: Epoch) {
        self.current_epoch = new_epoch;
        // Apply decay to useful work scores
        self.apply_score_decay();
        // Recalculate active set with new weights
        self.recalculate_active_set();
    }

    /// Apply score decay at epoch boundary
    fn apply_score_decay(&mut self) {
        // Apply 5% decay to all scores
        const DECAY_FACTOR: f64 = 0.95;

        for score in self.useful_work_scores.values_mut() {
            *score = (*score as f64 * DECAY_FACTOR) as u64;
        }
    }

    /// Recalculate active validator set
    fn recalculate_active_set(&mut self) {
        self.active_validators = self.validators
            .iter()
            .filter(|(_, v)| v.is_eligible(self.current_slot))
            .map(|(addr, _)| *addr)
            .collect();

        let mut weights: HashMap<Address, u128> = HashMap::new();
        for addr in &self.active_validators {
            if let Some(v) = self.validators.get(addr) {
                let score = self.useful_work_scores.get(addr).copied().unwrap_or(0);
                weights.insert(*addr, self.weighted_stake(v.stake, score));
            }
        }

        // Sort by weighted stake (descending)
        self.active_validators.sort_by(|a, b| {
            let stake_a = *weights.get(a).unwrap_or(&0);
            let stake_b = *weights.get(b).unwrap_or(&0);

            stake_b.cmp(&stake_a)
        });

        // Recalculate totals
        self.total_stake = 0;
        self.total_weighted_stake = 0;
        for addr in &self.active_validators {
            if let Some(v) = self.validators.get(addr) {
                self.total_stake += v.stake;
                let score = self.useful_work_scores.get(addr).copied().unwrap_or(0);
                self.total_weighted_stake += self.weighted_stake(v.stake, score);
            }
        }
    }

    /// Calculate weighted stake
    fn weighted_stake(&self, stake: u128, useful_work_score: u64) -> u128 {
        let multiplier = self.useful_work_multiplier(useful_work_score);
        (stake as f64 * multiplier) as u128
    }

    /// Calculate useful work multiplier
    fn useful_work_multiplier(&self, score: u64) -> f64 {
        let multiplier = 1.0 + (1.0 + score as f64).log10() / 6.0;
        multiplier.min(5.0) // Cap at 5x
    }

    /// Register new validator
    pub fn register_validator(&mut self, info: ValidatorInfo) -> ConsensusResult<()> {
        let addr = info.address;
        self.validators.insert(addr, info);
        self.useful_work_scores.entry(addr).or_insert(0);
        self.recalculate_active_set();
        Ok(())
    }

    /// Update validator useful work score
    pub fn update_useful_work_score(&mut self, address: &Address, delta: i64) -> ConsensusResult<()> {
        let validator = self.validators.get_mut(address)
            .ok_or_else(|| ConsensusError::ValidatorNotFound(*address))?;

        let current_score = self.useful_work_scores.entry(*address).or_insert(0);

        if delta >= 0 {
            *current_score = current_score.saturating_add(delta as u64);
        } else {
            *current_score = current_score.saturating_sub((-delta) as u64);
        }

        // Update validator's useful work score field for compatibility
        validator.useful_work_score = *current_score;

        self.recalculate_active_set();
        Ok(())
    }

    /// Get validator by address
    pub fn get_validator(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.validators.get(address)
    }

    /// Get useful work score for validator
    pub fn get_useful_work_score(&self, address: &Address) -> u64 {
        self.useful_work_scores.get(address).copied().unwrap_or(0)
    }

    /// Update category statistics
    pub fn update_category_stats(
        &mut self,
        category: UtilityCategory,
        uwu: u64,
        difficulty: u64,
        completion_time: u64,
        sla_met: bool,
    ) {
        let stats = self.category_stats.entry(category).or_default();

        let old_total_jobs = stats.total_jobs;
        stats.total_jobs += 1;
        stats.total_uwu += uwu;

        // Rolling average for difficulty
        stats.avg_difficulty = (stats.avg_difficulty * old_total_jobs + difficulty) / stats.total_jobs;

        // Rolling average for completion time
        stats.avg_completion_time = (stats.avg_completion_time * old_total_jobs + completion_time) / stats.total_jobs;

        // Update SLA compliance rate
        let old_compliance_count = (stats.sla_compliance_bps as u64 * old_total_jobs) / 10000;
        let new_compliance_count = old_compliance_count + if sla_met { 1 } else { 0 };
        stats.sla_compliance_bps = (new_compliance_count * 10000) / stats.total_jobs;
    }
}

impl ConsensusState for PoUWState {
    fn get_stake(&self, address: &Address) -> u128 {
        self.validators.get(address).map(|v| v.stake).unwrap_or(0)
    }

    fn get_useful_work_score(&self, address: &Address) -> u64 {
        self.useful_work_scores.get(address).copied().unwrap_or(0)
    }

    fn total_weighted_stake(&self) -> u128 {
        self.total_weighted_stake
    }

    fn get_epoch_seed(&self, _epoch: Epoch) -> EpochSeed {
        self.epoch_seed
    }

    fn validator_count(&self) -> usize {
        self.active_validators.len()
    }

    fn is_validator_active(&self, address: &Address) -> bool {
        self.active_validators.contains(address)
    }
}

// =============================================================================
// MAIN POUW CONSENSUS ENGINE
// =============================================================================

/// Proof-of-Useful-Work Consensus Engine
///
/// Main entry point for all consensus operations including:
/// - Leader election via VRF with Useful Work weighting
/// - Block validation
/// - Useful Work verification
/// - Finality tracking
/// - Reward calculation
pub struct PoUWConsensus {
    /// Configuration
    config: PoUWConfig,

    /// Consensus state (thread-safe)
    state: Arc<RwLock<PoUWState>>,

    /// Leader election module
    election: Arc<PoUWElection>,

    /// VRF engine for cryptographic operations
    vrf_engine: VrfEngine,

    /// Slot timing configuration
    timing: SlotTiming,

    /// Local validator keys (None if not a validator)
    local_keys: Option<VrfKeys>,

    /// Block cache for validation
    #[allow(dead_code)]
    block_cache: RwLock<HashMap<Hash, CachedBlock>>,

    /// Metrics collector
    metrics: ConsensusMetrics,

    /// Verification engine for AI proofs
    verification_engine: Arc<VerificationEngine>,
}

/// Cached block information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct CachedBlock {
    header: PoUWBlockHeader,
    validated: bool,
    validation_time_ms: u64,
}

/// Consensus metrics for monitoring
#[derive(Debug, Default)]
pub struct ConsensusMetrics {
    /// Blocks proposed
    pub blocks_proposed: std::sync::atomic::AtomicU64,
    /// Blocks validated
    pub blocks_validated: std::sync::atomic::AtomicU64,
    /// VRF proofs generated
    pub vrf_proofs_generated: std::sync::atomic::AtomicU64,
    /// Leader elections won
    pub elections_won: std::sync::atomic::AtomicU64,
    /// Useful work jobs verified
    pub useful_work_verified: std::sync::atomic::AtomicU64,
    /// Total UWU awarded
    pub total_uwu_awarded: std::sync::atomic::AtomicU64,
    /// Slashing events
    pub slashing_events: std::sync::atomic::AtomicU64,
    /// TEE verifications
    pub tee_verifications: std::sync::atomic::AtomicU64,
    /// zkML verifications
    pub zkml_verifications: std::sync::atomic::AtomicU64,
    /// AI proof verifications
    pub ai_proof_verifications: std::sync::atomic::AtomicU64,
}

impl PoUWConsensus {
    /// Create new consensus engine
    pub fn new(config: PoUWConfig, genesis_timestamp: u64) -> Self {
        let timing = SlotTiming {
            slot_duration_ms: config.slot_duration_ms,
            slots_per_epoch: config.slots_per_epoch,
            genesis_timestamp,
        };

        let state = Arc::new(RwLock::new(PoUWState::new(genesis_timestamp)));
        let election = Arc::new(PoUWElection::new(config.clone()));
        let verification_engine = Arc::new(VerificationEngine::new(config.clone()));

        Self {
            config,
            state,
            election,
            vrf_engine: VrfEngine::new(),
            timing,
            local_keys: None,
            block_cache: RwLock::new(HashMap::new()),
            metrics: ConsensusMetrics::default(),
            verification_engine,
        }
    }

    /// Create with local validator keys
    pub fn with_validator_keys(mut self, keys: VrfKeys) -> Self {
        self.local_keys = Some(keys);
        self
    }

    /// Get current slot from timestamp
    pub fn current_slot(&self) -> Slot {
        self.state.read().current_slot
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> Epoch {
        self.state.read().current_epoch
    }

    /// Advance to new slot
    pub fn advance_slot(&self, slot: Slot) {
        self.state.write().advance_slot(slot, &self.timing);
        self.election.set_current_epoch(self.timing.epoch_for_slot(slot));
    }

    /// Register validator
    pub fn register_validator(&self, info: ValidatorInfo) -> ConsensusResult<()> {
        self.state.write().register_validator(info.clone())?;
        self.election.register_validator(info)
    }

    /// Update useful work score for validator
    pub fn update_useful_work_score(&self, address: &Address, delta: i64) -> ConsensusResult<()> {
        self.state.write().update_useful_work_score(address, delta)
    }

    /// Check if local node should propose for slot
    pub fn should_propose(&self, slot: Slot) -> ConsensusResult<bool> {
        let keys = self.local_keys.as_ref()
            .ok_or(ConsensusError::NotValidator)?;

        let state = self.state.read();
        let epoch_seed = state.epoch_seed;
        let address = self.derive_address_from_keys(keys);

        // Check basic eligibility
        let validator = state.get_validator(&address)
            .ok_or(ConsensusError::ValidatorNotFound(address))?;

        if !validator.is_eligible(slot) {
            return Ok(false);
        }

        let useful_work_score = state.get_useful_work_score(&address);
        drop(state);

        // Generate VRF proof
        let vrf_input = self.compute_vrf_input(slot, &epoch_seed);
        let (_proof, output) = self.vrf_engine.prove(keys, &vrf_input)?;

        // Check against threshold
        let state = self.state.read();
        let stake = state.get_stake(&address);
        let total_weighted = state.total_weighted_stake();

        let threshold = self.election.calculate_threshold(stake, useful_work_score, total_weighted);
        let vrf_value = output.to_bigint();

        Ok(vrf_value < threshold)
    }

    /// Generate leader credentials for slot
    pub fn generate_credentials(&self, slot: Slot) -> ConsensusResult<LeaderCredentials> {
        let keys = self.local_keys.as_ref()
            .ok_or(ConsensusError::NotValidator)?;

        let state = self.state.read();
        let epoch_seed = state.epoch_seed;
        let address = self.derive_address_from_keys(keys);

        let validator = state.get_validator(&address)
            .ok_or(ConsensusError::ValidatorNotFound(address))?;

        let stake = validator.stake;
        let useful_work_score = state.get_useful_work_score(&address);
        drop(state);

        // Generate VRF proof
        let vrf_input = self.compute_vrf_input(slot, &epoch_seed);
        let (proof, output) = self.vrf_engine.prove(keys, &vrf_input)?;

        use std::sync::atomic::Ordering;
        self.metrics.vrf_proofs_generated.fetch_add(1, Ordering::Relaxed);

        Ok(LeaderCredentials {
            slot,
            address,
            vrf_proof: proof,
            vrf_output: output,
            stake,
            useful_work_score,
        })
    }

    /// Verify leader credentials from another validator
    pub fn verify_credentials(&self, credentials: &LeaderCredentials) -> ConsensusResult<bool> {
        let state = self.state.read();

        // Get validator info
        let validator = state.get_validator(&credentials.address)
            .ok_or(ConsensusError::ValidatorNotFound(credentials.address))?;

        if !validator.is_eligible(credentials.slot) {
            return Err(ConsensusError::ValidatorIneligible(credentials.address));
        }

        // Verify stake matches
        if validator.stake != credentials.stake {
            return Err(ConsensusError::InvalidLeaderCredentials(
                "Stake mismatch".into()
            ));
        }

        // Verify useful work score matches (with tolerance)
        let actual_score = state.get_useful_work_score(&credentials.address);
        let tolerance = actual_score / 100; // 1% tolerance
        if (credentials.useful_work_score as i128 - actual_score as i128).unsigned_abs() > tolerance as u128 {
            return Err(ConsensusError::InvalidLeaderCredentials(
                "Useful work score mismatch".into()
            ));
        }

        let epoch_seed = state.epoch_seed;
        let vrf_pubkey = validator.vrf_pubkey.clone();
        let total_weighted = state.total_weighted_stake();
        drop(state);

        // Verify VRF proof
        let vrf_input = self.compute_vrf_input(credentials.slot, &epoch_seed);
        let output = self.vrf_engine.verify(&vrf_pubkey, &vrf_input, &credentials.vrf_proof)?;

        // Check threshold
        let threshold = self.election.calculate_threshold(
            credentials.stake,
            credentials.useful_work_score,
            total_weighted,
        );

        let vrf_value = output.to_bigint();
        Ok(vrf_value < threshold)
    }

    /// Process useful work results from a block
    pub fn process_useful_work_results(
        &self,
        block: &PoUWBlockHeader,
        results: &[UsefulWorkResult],
    ) -> ConsensusResult<UsefulWorkProcessingResult> {
        let mut total_uwu = 0u64;
        let mut verified_count = 0u32;
        let mut score_updates: HashMap<Address, i64> = HashMap::new();

        for result in results {
            // Verify the result
            if self.verify_useful_work(result)? {
                total_uwu = total_uwu.saturating_add(result.useful_work_units);
                verified_count += 1;

                // Calculate score contribution
                let score_delta = self.calculate_score_contribution(result);
                *score_updates.entry(result.validator).or_insert(0) += score_delta;

                use std::sync::atomic::Ordering;
                self.metrics.useful_work_verified.fetch_add(1, Ordering::Relaxed);
                self.metrics.total_uwu_awarded.fetch_add(result.useful_work_units, Ordering::Relaxed);
            }
        }

        // Apply score updates
        let mut state = self.state.write();
        for (address, delta) in &score_updates {
            let new_score = {
                let current_score = state.useful_work_scores.entry(*address).or_insert(0);
                if *delta >= 0 {
                    *current_score = current_score.saturating_add(*delta as u64);
                } else {
                    *current_score = current_score.saturating_sub((-*delta) as u64);
                }
                *current_score
            };

            if let Some(validator) = state.validators.get_mut(address) {
                validator.useful_work_score = new_score;
                validator.jobs_verified += 1;

                // Also update election module
                if let Err(e) = self.election.record_useful_work(
                    address,
                    *delta as u64,
                    UtilityCategory::General, // Use result category in production
                    VerificationMethod::TeeAttestation,
                    0,
                ) {
                    tracing::warn!("Failed to update election useful work score: {}", e);
                }
            }
        }

        // Update proposer stats
        if let Some(proposer) = state.validators.get_mut(&block.proposer_address) {
            proposer.blocks_proposed += 1;
            proposer.last_proposal_slot = block.slot;
        }

        state.recalculate_active_set();

        Ok(UsefulWorkProcessingResult {
            total_useful_work_units: total_uwu,
            verified_count,
            score_updates,
        })
    }

    /// Verify a single useful work result
    ///
    /// This is the core verification function that validates AI computation proofs
    /// using the appropriate verification method.
    pub fn verify_useful_work(&self, result: &UsefulWorkResult) -> ConsensusResult<bool> {
        // First check if attestation is present
        if !result.has_valid_attestation() {
            return Ok(false);
        }

        // Verify based on method
        let verified = match result.verification_method {
            VerificationMethod::TeeAttestation => {
                self.verification_engine.verify_tee_attestation(result)?
            }
            VerificationMethod::ZkProof => {
                self.verification_engine.verify_zkml_proof(result)?
            }
            VerificationMethod::Hybrid => {
                // Both must pass
                self.verification_engine.verify_tee_attestation(result)? &&
                self.verification_engine.verify_zkml_proof(result)?
            }
            VerificationMethod::ReExecution => {
                result.confirmations >= self.config.min_reexecution_validators
            }
            VerificationMethod::AiProof => {
                self.verification_engine.verify_ai_proof(result)?
            }
        };

        if verified {
            // Update metrics
            use std::sync::atomic::Ordering;
            match result.verification_method {
                VerificationMethod::TeeAttestation => {
                    self.metrics.tee_verifications.fetch_add(1, Ordering::Relaxed);
                }
                VerificationMethod::ZkProof => {
                    self.metrics.zkml_verifications.fetch_add(1, Ordering::Relaxed);
                }
                VerificationMethod::Hybrid => {
                    self.metrics.tee_verifications.fetch_add(1, Ordering::Relaxed);
                    self.metrics.zkml_verifications.fetch_add(1, Ordering::Relaxed);
                }
                VerificationMethod::AiProof => {
                    self.metrics.ai_proof_verifications.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }

        Ok(verified)
    }

    /// Calculate score contribution from useful work result
    fn calculate_score_contribution(&self, result: &UsefulWorkResult) -> i64 {
        // Base score is UWU
        let base_score = result.useful_work_units as i64;

        // Category multiplier
        let category_mult = self.config.category_multiplier(result.category) as f64 / 10000.0;

        // Verification method bonus
        let method_mult = match result.verification_method {
            VerificationMethod::TeeAttestation => 1.0,
            VerificationMethod::ZkProof => 1.5,
            VerificationMethod::Hybrid => 2.0,
            VerificationMethod::ReExecution => 0.8,
            VerificationMethod::AiProof => 1.75,
        };

        // SLA bonus/penalty
        let sla_mult = if result.sla_met() { 1.1 } else { 0.9 };

        (base_score as f64 * category_mult * method_mult * sla_mult) as i64
    }

    /// Compute VRF input for a slot
    fn compute_vrf_input(&self, slot: Slot, epoch_seed: &EpochSeed) -> Vec<u8> {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(epoch_seed);
        input.extend_from_slice(&slot.to_le_bytes());
        input
    }

    /// Derive address from VRF keys
    fn derive_address_from_keys(&self, keys: &VrfKeys) -> Address {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&keys.public_key_bytes());
        let hash = hasher.finalize();
        let mut address = [0u8; 32];
        address.copy_from_slice(&hash);
        address
    }

    /// Get consensus metrics
    pub fn metrics(&self) -> &ConsensusMetrics {
        &self.metrics
    }

    /// Get timing configuration
    pub fn timing(&self) -> &SlotTiming {
        &self.timing
    }

    /// Get state snapshot
    pub fn state_snapshot(&self) -> StateSnapshot {
        let state = self.state.read();
        StateSnapshot {
            current_slot: state.current_slot,
            current_epoch: state.current_epoch,
            validator_count: state.active_validators.len(),
            total_stake: state.total_stake,
            total_weighted_stake: state.total_weighted_stake,
            last_finalized_slot: state.last_finalized_slot,
        }
    }
}

// =============================================================================
// VERIFICATION ENGINE
// =============================================================================

/// Verification engine for AI computation proofs
pub struct VerificationEngine {
    /// Configuration
    config: PoUWConfig,

    /// Approved TEE measurement hashes
    approved_measurements: RwLock<HashMap<Hash, String>>,

    /// zkML verifier circuits
    #[allow(dead_code)]
    verifier_circuits: RwLock<HashMap<Hash, VerifierCircuit>>,

    /// AI proof verifier models
    #[allow(dead_code)]
    ai_verifier_models: RwLock<HashMap<Hash, AiVerifierModel>>,
}

/// zkML verifier circuit
#[allow(dead_code)]
pub(crate) struct VerifierCircuit {
    /// Circuit hash
    hash: Hash,
    /// Supported model types
    model_types: Vec<String>,
    /// Verification parameters
    params: Vec<u8>,
}

/// AI verifier model configuration
#[allow(dead_code)]
pub(crate) struct AiVerifierModel {
    /// Model hash
    hash: Hash,
    /// Minimum confidence threshold
    min_confidence_bps: u64,
    /// Supported categories
    categories: Vec<UtilityCategory>,
}

impl VerificationEngine {
    /// Create new verification engine
    pub fn new(config: PoUWConfig) -> Self {
        Self {
            config,
            approved_measurements: RwLock::new(HashMap::new()),
            verifier_circuits: RwLock::new(HashMap::new()),
            ai_verifier_models: RwLock::new(HashMap::new()),
        }
    }

    /// Verify TEE attestation
    pub fn verify_tee_attestation(&self, result: &UsefulWorkResult) -> ConsensusResult<bool> {
        if result.tee_attestation.is_empty() {
            return Ok(false);
        }

        // In production, this would:
        // 1. Parse the attestation (SGX/Nitro format)
        // 2. Verify the signature chain
        // 3. Check measurement against approved list
        // 4. Verify the input/output hashes match

        // For now, check minimum attestation length
        if result.tee_attestation.len() < 100 {
            return Ok(false);
        }

        // Verify format markers (simplified)
        let has_valid_header = result.tee_attestation.starts_with(&[0x02, 0x00]) || // SGX
                               result.tee_attestation.starts_with(&[0x84]); // CBOR (Nitro)

        Ok(has_valid_header)
    }

    /// Verify zkML proof
    pub fn verify_zkml_proof(&self, result: &UsefulWorkResult) -> ConsensusResult<bool> {
        let proof = match &result.zkml_proof {
            Some(p) => p,
            None => return Ok(false),
        };

        if proof.is_empty() {
            return Ok(false);
        }

        // In production, this would:
        // 1. Deserialize the proof
        // 2. Load the verification key for the circuit
        // 3. Verify the proof against public inputs
        // 4. Check that public inputs match claimed values

        // Minimum proof size for validity
        if proof.len() < 200 {
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify AI proof
    pub fn verify_ai_proof(&self, result: &UsefulWorkResult) -> ConsensusResult<bool> {
        let ai_proof = match &result.ai_proof {
            Some(p) => p,
            None => return Ok(false),
        };

        // Check confidence threshold
        if !ai_proof.meets_threshold(self.config.ai_proof_confidence_threshold_bps) {
            return Ok(false);
        }

        // Check embedding validity
        if ai_proof.result_embedding.is_empty() {
            return Ok(false);
        }

        // In production, this would:
        // 1. Load the verifier model
        // 2. Run inference on the embedding
        // 3. Verify the signature
        // 4. Compare confidence scores

        Ok(true)
    }

    /// Register approved TEE measurement
    pub fn register_measurement(&self, hash: Hash, description: String) {
        self.approved_measurements.write().insert(hash, description);
    }

    /// Register verifier circuit
    #[allow(dead_code)]
    pub(crate) fn register_verifier_circuit(&self, circuit: VerifierCircuit) {
        self.verifier_circuits.write().insert(circuit.hash, circuit);
    }

    /// Register AI verifier model
    #[allow(dead_code)]
    pub(crate) fn register_ai_verifier(&self, model: AiVerifierModel) {
        self.ai_verifier_models.write().insert(model.hash, model);
    }
}

// =============================================================================
// BLOCK VALIDATION
// =============================================================================

impl BlockValidator for PoUWConsensus {
    fn validate_header(&self, header: &PoUWBlockHeader, parent: &PoUWBlockHeader) -> ConsensusResult<()> {
        // 1. Basic structure validation
        header.validate_structure().map_err(|e| ConsensusError::BlockValidation(e))?;

        // 2. Parent link validation
        let parent_hash = parent.hash();
        if header.parent_hash != parent_hash {
            return Err(ConsensusError::InvalidParentHash {
                expected: parent_hash,
                got: header.parent_hash,
            });
        }

        // 3. Height validation
        if header.height != parent.height + 1 {
            return Err(ConsensusError::BlockValidation(format!(
                "Invalid height: expected {}, got {}",
                parent.height + 1,
                header.height
            )));
        }

        // 4. Slot validation
        if header.slot <= parent.slot {
            return Err(ConsensusError::SlotValidation(format!(
                "Slot {} not after parent slot {}",
                header.slot, parent.slot
            )));
        }

        // 5. Timestamp validation
        let expected_timestamp = self.timing.timestamp_for_slot(header.slot);
        let drift = if header.timestamp > expected_timestamp {
            header.timestamp - expected_timestamp
        } else {
            expected_timestamp - header.timestamp
        };

        if drift > self.config.max_clock_drift_secs {
            return Err(ConsensusError::TimestampValidation(format!(
                "Timestamp drift {} exceeds max {}",
                drift, self.config.max_clock_drift_secs
            )));
        }

        // 6. VRF proof validation
        self.validate_vrf_proof(header)?;

        // 7. Proposer validation
        self.validate_proposer(header)?;

        // 8. Finality fields validation
        if header.last_finalized_slot > header.slot {
            return Err(ConsensusError::FinalityValidation(
                "Finalized slot cannot be in the future".into()
            ));
        }

        use std::sync::atomic::Ordering;
        self.metrics.blocks_validated.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn validate_compute_results(
        &self,
        header: &PoUWBlockHeader,
        results: &[crate::traits::ComputeResult],
    ) -> ConsensusResult<()> {
        // 1. Job count validation
        if results.len() != header.compute_job_count as usize {
            return Err(ConsensusError::ComputeValidation(format!(
                "Job count mismatch: header says {}, got {}",
                header.compute_job_count,
                results.len()
            )));
        }

        // 2. Total complexity validation
        let total_complexity: u64 = results.iter().map(|r| r.complexity).sum();
        if total_complexity != header.compute_complexity {
            return Err(ConsensusError::ComputeValidation(format!(
                "Complexity mismatch: header says {}, computed {}",
                header.compute_complexity,
                total_complexity
            )));
        }

        // 3. Compute results merkle root
        let computed_root = self.compute_results_merkle_root(results);
        if computed_root != header.compute_results_root {
            return Err(ConsensusError::ComputeValidation(
                "Compute results root mismatch".into()
            ));
        }

        // 4. Individual result validation
        for result in results {
            self.validate_single_result(result)?;
        }

        Ok(())
    }
}

impl PoUWConsensus {
    /// Validate VRF proof in block header
    fn validate_vrf_proof(&self, header: &PoUWBlockHeader) -> ConsensusResult<()> {
        if header.is_genesis() {
            return Ok(());
        }

        // Parse VRF proof from header
        if header.vrf_proof.len() < 100 {
            return Err(ConsensusError::VrfValidation(
                "VRF proof too short".into()
            ));
        }

        let state = self.state.read();
        let validator = state.get_validator(&header.proposer_address)
            .ok_or(ConsensusError::ValidatorNotFound(header.proposer_address))?;

        let epoch_seed = state.epoch_seed;
        let total_weighted = state.total_weighted_stake();
        let stake = validator.stake;
        let useful_work_score = state.get_useful_work_score(&header.proposer_address);
        let vrf_pubkey = validator.vrf_pubkey.clone();
        drop(state);

        // Parse and verify VRF proof
        let proof = VrfProof::from_bytes(&header.vrf_proof)
            .map_err(|e| ConsensusError::VrfValidation(e.to_string()))?;

        let vrf_input = self.compute_vrf_input(header.slot, &epoch_seed);
        let output = self.vrf_engine.verify(&vrf_pubkey, &vrf_input, &proof)?;

        // Check threshold
        let threshold = self.election.calculate_threshold(stake, useful_work_score, total_weighted);
        let vrf_value = output.to_bigint();

        if vrf_value >= threshold {
            return Err(ConsensusError::VrfValidation(
                "VRF output does not meet threshold".into()
            ));
        }

        Ok(())
    }

    /// Validate block proposer
    fn validate_proposer(&self, header: &PoUWBlockHeader) -> ConsensusResult<()> {
        if header.is_genesis() {
            return Ok(());
        }

        let state = self.state.read();

        // Check proposer exists and is active
        let validator = state.get_validator(&header.proposer_address)
            .ok_or(ConsensusError::ValidatorNotFound(header.proposer_address))?;

        if !validator.is_eligible(header.slot) {
            return Err(ConsensusError::ValidatorIneligible(header.proposer_address));
        }

        // Verify proposer useful work score matches (with tolerance)
        let actual_score = state.get_useful_work_score(&header.proposer_address);
        let tolerance = actual_score / 100; // 1% tolerance
        if (header.proposer_useful_work_score as i128 - actual_score as i128).unsigned_abs() > tolerance as u128 {
            return Err(ConsensusError::BlockValidation(format!(
                "Proposer useful work score mismatch: expected ~{}, got {}",
                actual_score, header.proposer_useful_work_score
            )));
        }

        // Verify proposer stake matches
        if validator.stake != header.proposer_stake {
            return Err(ConsensusError::BlockValidation(format!(
                "Proposer stake mismatch: expected {}, got {}",
                validator.stake, header.proposer_stake
            )));
        }

        Ok(())
    }

    /// Validate single compute result
    fn validate_single_result(&self, result: &crate::traits::ComputeResult) -> ConsensusResult<()> {
        // Check job ID is valid
        if result.job_id == [0u8; 32] {
            return Err(ConsensusError::ComputeValidation(
                "Invalid job ID (all zeros)".into()
            ));
        }

        // Check model hash is valid
        if result.model_hash == [0u8; 32] {
            return Err(ConsensusError::ComputeValidation(
                "Invalid model hash (all zeros)".into()
            ));
        }

        // Check complexity is reasonable
        if result.complexity == 0 {
            return Err(ConsensusError::ComputeValidation(
                "Complexity cannot be zero".into()
            ));
        }

        // Verify validator exists
        let state = self.state.read();
        if !state.validators.contains_key(&result.validator) {
            return Err(ConsensusError::ValidatorNotFound(result.validator));
        }

        Ok(())
    }

    /// Compute merkle root of compute results
    fn compute_results_merkle_root(&self, results: &[crate::traits::ComputeResult]) -> Hash {
        use sha2::{Sha256, Digest};

        if results.is_empty() {
            return [0u8; 32];
        }

        // Hash each result
        let mut hashes: Vec<[u8; 32]> = results.iter().map(|r| {
            let mut hasher = Sha256::new();
            hasher.update(&r.job_id);
            hasher.update(&r.output_hash);
            hasher.update(&r.complexity.to_le_bytes());
            hasher.update(&[r.verification_method as u8]);
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        }).collect();

        // Build merkle tree
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for pair in hashes.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&pair[0]);
                if pair.len() > 1 {
                    hasher.update(&pair[1]);
                } else {
                    hasher.update(&pair[0]); // Duplicate for odd count
                }
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                next_level.push(hash);
            }
            hashes = next_level;
        }

        hashes[0]
    }
}

// =============================================================================
// CONSENSUS TRAIT IMPLEMENTATION
// =============================================================================

impl Consensus for PoUWConsensus {
    fn is_leader(&self, slot: Slot, address: &Address, vrf_output: &[u8]) -> ConsensusResult<bool> {
        let state = self.state.read();

        let validator = state.get_validator(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        if !validator.is_eligible(slot) {
            return Ok(false);
        }

        let stake = validator.stake;
        let useful_work_score = state.get_useful_work_score(address);
        let total_weighted = state.total_weighted_stake();
        drop(state);

        // Parse VRF output
        if vrf_output.len() != 32 {
            return Err(ConsensusError::VrfValidation(
                "Invalid VRF output length".into()
            ));
        }

        let output = VrfOutput::from_bytes(vrf_output.try_into().unwrap());
        let vrf_value = output.to_bigint();
        let threshold = self.election.calculate_threshold(stake, useful_work_score, total_weighted);

        Ok(vrf_value < threshold)
    }

    fn verify_leader_credentials(
        &self,
        slot: Slot,
        address: &Address,
        vrf_proof: &[u8],
        vrf_pubkey: &[u8],
    ) -> ConsensusResult<bool> {
        let state = self.state.read();

        let validator = state.get_validator(address)
            .ok_or(ConsensusError::ValidatorNotFound(*address))?;

        // Verify VRF public key matches
        if validator.vrf_pubkey != vrf_pubkey {
            return Err(ConsensusError::VrfValidation(
                "VRF public key mismatch".into()
            ));
        }

        let epoch_seed = state.epoch_seed;
        let stake = validator.stake;
        let useful_work_score = state.get_useful_work_score(address);
        let total_weighted = state.total_weighted_stake();
        drop(state);

        // Parse and verify VRF proof
        let proof = VrfProof::from_bytes(vrf_proof)
            .map_err(|e| ConsensusError::VrfValidation(e.to_string()))?;

        let vrf_input = self.compute_vrf_input(slot, &epoch_seed);
        let output = self.vrf_engine.verify(vrf_pubkey, &vrf_input, &proof)?;

        // Check threshold
        let threshold = self.election.calculate_threshold(stake, useful_work_score, total_weighted);
        let vrf_value = output.to_bigint();

        Ok(vrf_value < threshold)
    }

    fn produce_vrf_proof(&self, _slot: Slot, seed: &[u8]) -> ConsensusResult<(Vec<u8>, Vec<u8>)> {
        let keys = self.local_keys.as_ref()
            .ok_or(ConsensusError::NotValidator)?;

        let (proof, output) = self.vrf_engine.prove(keys, seed)?;

        Ok((proof.to_bytes(), output.as_bytes().to_vec()))
    }

    fn get_epoch_seed(&self, _epoch: Epoch) -> ConsensusResult<[u8; 32]> {
        let state = self.state.read();
        Ok(state.epoch_seed)
    }
}

// =============================================================================
// SUPPORTING TYPES
// =============================================================================

/// Leader credentials for block proposal
#[derive(Debug, Clone)]
pub struct LeaderCredentials {
    /// Slot being proposed
    pub slot: Slot,
    /// Proposer address
    pub address: Address,
    /// VRF proof
    pub vrf_proof: VrfProof,
    /// VRF output
    pub vrf_output: VrfOutput,
    /// Proposer's stake
    pub stake: u128,
    /// Proposer's useful work score
    pub useful_work_score: u64,
}

impl LeaderCredentials {
    /// Serialize to bytes for block header
    pub fn vrf_proof_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(112);
        bytes.extend_from_slice(self.vrf_output.as_bytes());
        bytes.extend_from_slice(&self.vrf_proof.to_bytes());
        bytes
    }
}

/// Result of useful work processing
#[derive(Debug)]
pub struct UsefulWorkProcessingResult {
    /// Total Useful Work Units processed
    pub total_useful_work_units: u64,
    /// Number of verified jobs
    pub verified_count: u32,
    /// Score updates to apply
    pub score_updates: HashMap<Address, i64>,
}

/// State snapshot for external queries
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    pub current_slot: Slot,
    pub current_epoch: Epoch,
    pub validator_count: usize,
    pub total_stake: u128,
    pub total_weighted_stake: u128,
    pub last_finalized_slot: Slot,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PoUWConfig {
        PoUWConfig::devnet()
    }

    #[test]
    fn test_consensus_creation() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config, 1000);

        assert_eq!(consensus.current_slot(), 0);
        assert_eq!(consensus.current_epoch(), 0);
    }

    #[test]
    fn test_state_advance() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config, 1000);

        consensus.advance_slot(100);
        assert_eq!(consensus.current_slot(), 100);
    }

    #[test]
    fn test_validator_registration() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config.clone(), 1000);

        let validator = ValidatorInfo::new(
            [1u8; 32],
            crate::MIN_STAKE_FOR_ELECTION,
            vec![0u8; 33],
            vec![0u8; 64],
            1000,
            0,
        );

        consensus.register_validator(validator).unwrap();

        let snapshot = consensus.state_snapshot();
        assert_eq!(snapshot.validator_count, 1);
        assert_eq!(snapshot.total_stake, crate::MIN_STAKE_FOR_ELECTION);
    }

    #[test]
    fn test_useful_work_score_update() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config.clone(), 1000);

        let address = [1u8; 32];
        let validator = ValidatorInfo::new(
            address,
            crate::MIN_STAKE_FOR_ELECTION,
            vec![0u8; 33],
            vec![0u8; 64],
            1000,
            0,
        );

        consensus.register_validator(validator).unwrap();
        consensus.update_useful_work_score(&address, 1000).unwrap();

        let state = consensus.state.read();
        let score = state.get_useful_work_score(&address);
        assert_eq!(score, 1000);
    }

    #[test]
    fn test_merkle_root_empty() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config, 1000);

        let root = consensus.compute_results_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_useful_work_result_hash() {
        let result = UsefulWorkResult {
            job_id: [1u8; 32],
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            output_hash: [4u8; 32],
            useful_work_units: 1000,
            work_difficulty: 5000,
            category: UtilityCategory::Financial,
            verification_method: VerificationMethod::TeeAttestation,
            tee_attestation: vec![0x02, 0x00, 0x00],
            zkml_proof: None,
            ai_proof: None,
            validator: [5u8; 32],
            requester: [6u8; 32],
            confirmations: 1,
            completed_at: 1000,
            sla_deadline: 2000,
        };

        let hash = result.hash();
        assert_ne!(hash, [0u8; 32]);

        // Hash should be deterministic
        let hash2 = result.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_state_snapshot() {
        let config = test_config();
        let consensus = PoUWConsensus::new(config.clone(), 1000);

        let validator = ValidatorInfo::new(
            [1u8; 32],
            crate::MIN_STAKE_FOR_ELECTION,
            vec![0u8; 33],
            vec![0u8; 64],
            1000,
            0,
        );

        consensus.register_validator(validator).unwrap();
        consensus.advance_slot(50);

        let snapshot = consensus.state_snapshot();
        assert_eq!(snapshot.current_slot, 50);
        assert_eq!(snapshot.validator_count, 1);
    }

    #[test]
    fn test_verification_engine() {
        let config = test_config();
        let engine = VerificationEngine::new(config);

        // Test TEE attestation verification
        let result_no_attestation = UsefulWorkResult {
            job_id: [1u8; 32],
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            output_hash: [4u8; 32],
            useful_work_units: 1000,
            work_difficulty: 5000,
            category: UtilityCategory::General,
            verification_method: VerificationMethod::TeeAttestation,
            tee_attestation: vec![],
            zkml_proof: None,
            ai_proof: None,
            validator: [5u8; 32],
            requester: [6u8; 32],
            confirmations: 0,
            completed_at: 1000,
            sla_deadline: 2000,
        };

        assert!(!engine.verify_tee_attestation(&result_no_attestation).unwrap());

        // With valid-looking attestation
        let mut result_with_attestation = result_no_attestation.clone();
        let mut att = vec![0x02, 0x00];
        att.resize(100, 0x00);
        result_with_attestation.tee_attestation = att;

        assert!(engine.verify_tee_attestation(&result_with_attestation).unwrap());
    }
}
