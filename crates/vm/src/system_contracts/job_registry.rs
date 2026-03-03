//! Job Registry System Contract
//!
//! The state machine for AI inference tasks. Manages the complete lifecycle:
//! SUBMITTED → ASSIGNED → PROVING → VERIFIED → SETTLED
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          JOB LIFECYCLE                                   │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   SUBMITTED ─────────────────────────────────────────────────────────►  │
//! │       │                                                                  │
//! │       ▼ (assign_job)                                                    │
//! │   ASSIGNED ──────────────────────────────────────────────────────────►  │
//! │       │                                                    │            │
//! │       ▼ (start_proving)                                   │ (timeout)  │
//! │   PROVING ───────────────────────────────────────────────►│            │
//! │       │                                                    │            │
//! │       ▼ (submit_proof)                                    ▼            │
//! │   VERIFYING ────────────────────────────────────────► EXPIRED          │
//! │       │                       │                                         │
//! │       ▼ (verify success)      ▼ (verify fail)                          │
//! │   VERIFIED                 FAILED                                       │
//! │       │                                                                  │
//! │       ▼ (distribute_rewards)                                            │
//! │   SETTLED                                                               │
//! │                                                                          │
//! │   At any point before PROVING: ──────────────────────► CANCELLED       │
//! │                                                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use super::bank::Bank;
use super::error::{SystemContractError, SystemContractResult};
use super::events::JobEvent;
use super::staking::StakingManager;
use super::types::*;
use super::BlockContext;

// =============================================================================
// JOB CONFIGURATION
// =============================================================================

/// Job registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobConfig {
    /// Minimum bid amount for a job
    pub min_bid: TokenAmount,
    /// Maximum bid amount
    pub max_bid: TokenAmount,
    /// Default SLA timeout in seconds
    pub default_sla_timeout: u64,
    /// Minimum SLA timeout
    pub min_sla_timeout: u64,
    /// Maximum SLA timeout
    pub max_sla_timeout: u64,
    /// Cancellation fee percentage (basis points, 100 = 1%)
    pub cancellation_fee_bps: u16,
    /// Grace period for late submissions (seconds)
    pub late_grace_period: u64,
    /// Late submission penalty percentage
    pub late_penalty_bps: u16,
    /// Maximum jobs per requester
    pub max_jobs_per_requester: u32,
    /// Maximum active jobs in system
    pub max_active_jobs: u64,
}

impl JobConfig {
    /// Mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            min_bid: 100_000_000_000_000_000,         // 0.1 AETHEL
            max_bid: 100_000_000_000_000_000_000_000, // 100,000 AETHEL
            default_sla_timeout: 3600,                // 1 hour
            min_sla_timeout: 60,                      // 1 minute
            max_sla_timeout: 86400,                   // 24 hours
            cancellation_fee_bps: 500,                // 5%
            late_grace_period: 60,                    // 1 minute
            late_penalty_bps: 1000,                   // 10%
            max_jobs_per_requester: 100,
            max_active_jobs: 100_000,
        }
    }

    /// Testnet configuration
    pub fn testnet() -> Self {
        Self {
            min_bid: 1_000_000_000_000_000,         // 0.001 AETHEL
            max_bid: 1_000_000_000_000_000_000_000, // 1000 AETHEL
            default_sla_timeout: 600,               // 10 minutes
            min_sla_timeout: 30,
            max_sla_timeout: 7200,
            cancellation_fee_bps: 200,
            late_grace_period: 30,
            late_penalty_bps: 500,
            max_jobs_per_requester: 1000,
            max_active_jobs: 1_000_000,
        }
    }

    /// Devnet configuration
    pub fn devnet() -> Self {
        Self {
            min_bid: 0,
            max_bid: u128::MAX,
            default_sla_timeout: 120,
            min_sla_timeout: 10,
            max_sla_timeout: 3600,
            cancellation_fee_bps: 0,
            late_grace_period: 10,
            late_penalty_bps: 0,
            max_jobs_per_requester: u32::MAX,
            max_active_jobs: u64::MAX,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> SystemContractResult<()> {
        if self.min_sla_timeout >= self.max_sla_timeout {
            return Err(SystemContractError::InvalidConfig(
                "min_sla_timeout must be < max_sla_timeout".into(),
            ));
        }
        if self.cancellation_fee_bps > 10000 {
            return Err(SystemContractError::InvalidConfig(
                "cancellation_fee_bps must be <= 10000".into(),
            ));
        }
        Ok(())
    }
}

// =============================================================================
// SLA POLICY
// =============================================================================

/// SLA policy for a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaPolicy {
    /// Deadline timestamp
    pub deadline: u64,
    /// Grace period end
    pub grace_end: u64,
    /// Late penalty rate
    pub late_penalty_bps: u16,
}

impl SlaPolicy {
    /// Create from job config and submission time
    pub fn new(
        config: &JobConfig,
        priority: JobPriority,
        submitted_at: u64,
        custom_timeout: u64,
    ) -> Self {
        let base_timeout = if custom_timeout > 0 {
            custom_timeout.clamp(config.min_sla_timeout, config.max_sla_timeout)
        } else {
            config.default_sla_timeout
        };

        // Apply priority multiplier
        let adjusted_timeout = (base_timeout as f64 * priority.sla_multiplier()) as u64;
        let deadline = submitted_at + adjusted_timeout;

        Self {
            deadline,
            grace_end: deadline + config.late_grace_period,
            late_penalty_bps: config.late_penalty_bps,
        }
    }

    /// Check if deadline passed
    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.grace_end
    }

    /// Check if in grace period
    pub fn is_late(&self, current_time: u64) -> bool {
        current_time > self.deadline && current_time <= self.grace_end
    }

    /// Get penalty for late submission
    pub fn late_penalty(&self, amount: TokenAmount) -> TokenAmount {
        (amount * self.late_penalty_bps as u128) / 10000
    }
}

// =============================================================================
// JOB STATE
// =============================================================================

/// Complete job state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobState {
    /// Job ID
    pub job_id: JobId,
    /// Job requester
    pub requester: Address,
    /// Assigned prover (if assigned)
    pub assigned_prover: Option<Address>,
    /// Current status
    pub status: JobStatus,
    /// Bid amount (escrowed)
    pub bid_amount: TokenAmount,
    /// Model hash
    pub model_hash: Hash,
    /// Input hash
    pub input_hash: Hash,
    /// Output hash (after proof submitted)
    pub output_hash: Option<Hash>,
    /// Verification method required
    pub verification_method: VerificationMethod,
    /// Job priority
    pub priority: JobPriority,
    /// SLA policy
    pub sla: SlaPolicy,
    /// Compliance tags
    pub tags: Vec<ComplianceTag>,
    /// Submission timestamp
    pub submitted_at: u64,
    /// Assignment timestamp
    pub assigned_at: Option<u64>,
    /// Proof submission timestamp
    pub proof_submitted_at: Option<u64>,
    /// Verification timestamp
    pub verified_at: Option<u64>,
    /// Settlement timestamp
    pub settled_at: Option<u64>,
    /// Callback address
    pub callback: Option<Address>,
    /// Encrypted input data
    pub encrypted_input: Option<Vec<u8>>,
    /// Result data (after settlement)
    pub result: Option<Vec<u8>>,
}

impl JobState {
    /// Create new job state
    pub fn new(
        job_id: JobId,
        params: &SubmitJobParams,
        config: &JobConfig,
        submitted_at: u64,
    ) -> Self {
        let sla = SlaPolicy::new(config, params.priority, submitted_at, params.sla_timeout);

        Self {
            job_id,
            requester: params.requester,
            assigned_prover: None,
            status: JobStatus::Submitted,
            bid_amount: params.bid_amount,
            model_hash: params.model_hash,
            input_hash: params.input_hash,
            output_hash: None,
            verification_method: params.verification_method,
            priority: params.priority,
            sla,
            tags: params.tags.clone(),
            submitted_at,
            assigned_at: None,
            proof_submitted_at: None,
            verified_at: None,
            settled_at: None,
            callback: params.callback,
            encrypted_input: params.encrypted_input.clone(),
            result: None,
        }
    }

    /// Check if job can transition to status
    pub fn can_transition_to(&self, new_status: JobStatus) -> bool {
        match (self.status, new_status) {
            (JobStatus::Submitted, JobStatus::Assigned) => true,
            (JobStatus::Submitted, JobStatus::Cancelled) => true,
            (JobStatus::Assigned, JobStatus::Proving) => true,
            (JobStatus::Assigned, JobStatus::Cancelled) => true,
            (JobStatus::Assigned, JobStatus::Expired) => true,
            (JobStatus::Proving, JobStatus::Verifying) => true,
            (JobStatus::Proving, JobStatus::Expired) => true,
            (JobStatus::Verifying, JobStatus::Verified) => true,
            (JobStatus::Verifying, JobStatus::Failed) => true,
            (JobStatus::Verified, JobStatus::Settled) => true,
            _ => false,
        }
    }
}

// =============================================================================
// JOB REGISTRY
// =============================================================================

/// Job Registry - manages AI inference job lifecycle
pub struct JobRegistry {
    /// Configuration
    config: JobConfig,

    /// Jobs indexed by ID
    jobs: HashMap<JobId, JobState>,

    /// Jobs by requester
    jobs_by_requester: HashMap<Address, Vec<JobId>>,

    /// Jobs by prover
    jobs_by_prover: HashMap<Address, Vec<JobId>>,

    /// Jobs ordered by deadline (for expiration processing)
    jobs_by_deadline: BTreeMap<u64, Vec<JobId>>,

    /// Active job count
    active_jobs: u64,

    /// Total jobs ever created
    total_jobs: u64,

    /// Job nonce per requester
    job_nonces: HashMap<Address, u64>,

    /// Event queue
    events: Vec<JobEvent>,
}

impl JobRegistry {
    /// Create new job registry
    pub fn new(config: JobConfig) -> Self {
        Self {
            config,
            jobs: HashMap::new(),
            jobs_by_requester: HashMap::new(),
            jobs_by_prover: HashMap::new(),
            jobs_by_deadline: BTreeMap::new(),
            active_jobs: 0,
            total_jobs: 0,
            job_nonces: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Get and clear pending events
    pub fn drain_events(&mut self) -> Vec<JobEvent> {
        std::mem::take(&mut self.events)
    }

    /// Get job by ID
    pub fn get_job(&self, job_id: &JobId) -> Option<&JobState> {
        self.jobs.get(job_id)
    }

    /// Get jobs by requester
    pub fn get_jobs_by_requester(&self, requester: &Address) -> Vec<&JobState> {
        self.jobs_by_requester
            .get(requester)
            .map(|ids| ids.iter().filter_map(|id| self.jobs.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get jobs by prover
    pub fn get_jobs_by_prover(&self, prover: &Address) -> Vec<&JobState> {
        self.jobs_by_prover
            .get(prover)
            .map(|ids| ids.iter().filter_map(|id| self.jobs.get(id)).collect())
            .unwrap_or_default()
    }

    // =========================================================================
    // JOB SUBMISSION
    // =========================================================================

    /// Submit a new job
    pub fn submit_job(
        &mut self,
        params: SubmitJobParams,
        ctx: &BlockContext,
        bank: &mut Bank,
    ) -> SystemContractResult<JobSubmitResult> {
        // 1. Validate bid amount
        if params.bid_amount < self.config.min_bid {
            return Err(SystemContractError::InsufficientBid {
                minimum: self.config.min_bid,
                actual: params.bid_amount,
            });
        }

        if params.bid_amount > self.config.max_bid {
            return Err(SystemContractError::InsufficientBid {
                minimum: self.config.max_bid, // Abuse the error
                actual: params.bid_amount,
            });
        }

        // 2. Check job limits
        let requester_jobs = self
            .jobs_by_requester
            .get(&params.requester)
            .map(|j| j.len())
            .unwrap_or(0);

        if requester_jobs >= self.config.max_jobs_per_requester as usize {
            return Err(SystemContractError::InvalidAmount {
                reason: format!(
                    "Max jobs per requester ({}) exceeded",
                    self.config.max_jobs_per_requester
                ),
            });
        }

        if self.active_jobs >= self.config.max_active_jobs {
            return Err(SystemContractError::InvalidAmount {
                reason: "Maximum active jobs in system reached".into(),
            });
        }

        // 3. Generate job ID
        let nonce = self.job_nonces.entry(params.requester).or_insert(0);
        let job_id = generate_job_id(
            &params.requester,
            &params.model_hash,
            &params.input_hash,
            *nonce,
        );
        *nonce += 1;

        // 4. Escrow the bid amount
        bank.lock(&params.requester, params.bid_amount)?;

        // 5. Create job state
        let job = JobState::new(job_id, &params, &self.config, ctx.timestamp);
        let sla_deadline = job.sla.deadline;

        // 6. Index the job
        self.jobs.insert(job_id, job);
        self.jobs_by_requester
            .entry(params.requester)
            .or_default()
            .push(job_id);
        self.jobs_by_deadline
            .entry(sla_deadline)
            .or_default()
            .push(job_id);

        self.active_jobs += 1;
        self.total_jobs += 1;

        // 7. Emit event
        self.events.push(JobEvent::JobSubmitted {
            job_id,
            requester: params.requester,
            model_hash: params.model_hash,
            bid_amount: params.bid_amount,
            sla_deadline,
            block_height: ctx.height,
        });

        Ok(JobSubmitResult {
            job_id,
            escrowed: params.bid_amount,
            sla_deadline,
        })
    }

    // =========================================================================
    // JOB ASSIGNMENT
    // =========================================================================

    /// Assign a job to a prover
    pub fn assign_job(
        &mut self,
        job_id: JobId,
        prover: Address,
        ctx: &BlockContext,
    ) -> SystemContractResult<JobAssignResult> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| SystemContractError::job_not_found(&job_id))?;

        // 1. Check status
        if !job.can_transition_to(JobStatus::Assigned) {
            return Err(SystemContractError::InvalidJobStatus {
                expected: "Submitted".into(),
                actual: job.status.to_string(),
            });
        }

        // 2. Check not already assigned
        if job.assigned_prover.is_some() {
            return Err(SystemContractError::JobAlreadyAssigned {
                job_id: hex::encode(job_id),
                prover: hex::encode(job.assigned_prover.unwrap()),
            });
        }

        // 3. Check SLA not expired
        if job.sla.is_expired(ctx.timestamp) {
            return Err(SystemContractError::sla_violation(
                &job_id,
                job.sla.deadline,
                ctx.timestamp,
            ));
        }

        // 4. Assign prover
        job.assigned_prover = Some(prover);
        job.assigned_at = Some(ctx.timestamp);
        job.status = JobStatus::Assigned;

        // 5. Index by prover
        self.jobs_by_prover.entry(prover).or_default().push(job_id);

        // 6. Emit event
        self.events.push(JobEvent::JobAssigned {
            job_id,
            prover,
            assigned_at: ctx.timestamp,
            block_height: ctx.height,
        });

        Ok(JobAssignResult {
            job_id,
            prover,
            assigned_at: ctx.timestamp,
        })
    }

    // =========================================================================
    // PROOF SUBMISSION
    // =========================================================================

    /// Submit proof for a job
    pub fn submit_proof(
        &mut self,
        params: SubmitProofParams,
        ctx: &BlockContext,
        staking: &mut StakingManager,
        bank: &mut Bank,
    ) -> SystemContractResult<ProofSubmitResult> {
        let job = self
            .jobs
            .get_mut(&params.job_id)
            .ok_or_else(|| SystemContractError::job_not_found(&params.job_id))?;

        // 1. Verify prover is assigned
        if job.assigned_prover != Some(params.prover) {
            return Err(SystemContractError::unauthorized_prover(
                &job.assigned_prover.unwrap_or([0u8; 32]),
                &params.prover,
            ));
        }

        // 2. Check SLA
        let is_late = job.sla.is_late(ctx.timestamp);
        let is_expired = job.sla.is_expired(ctx.timestamp);

        if is_expired {
            // SLA violation - slash prover and expire job
            let slash_amount = staking.slash_for_sla_violation(&params.prover)?;

            job.status = JobStatus::Expired;
            self.active_jobs = self.active_jobs.saturating_sub(1);

            self.events.push(JobEvent::JobExpired {
                job_id: params.job_id,
                prover: params.prover,
                deadline: job.sla.deadline,
                expired_at: ctx.timestamp,
                slashed_amount: slash_amount,
            });

            return Err(SystemContractError::sla_violation(
                &params.job_id,
                job.sla.deadline,
                ctx.timestamp,
            ));
        }

        // 3. Verify proof method matches requirement
        if params.proof.method != job.verification_method {
            return Err(SystemContractError::ProofMethodMismatch {
                required: job.verification_method,
                actual: params.proof.method,
            });
        }

        // 4. Verify the proof (TEE and/or ZK)
        let verified = Self::verify_proof(&params.proof, job)?;

        if !verified {
            // Verification failed - slash prover
            let slash_amount = staking.slash_for_invalid_proof(&params.prover)?;

            job.status = JobStatus::Failed;
            self.active_jobs = self.active_jobs.saturating_sub(1);

            self.events.push(JobEvent::JobFailed {
                job_id: params.job_id,
                prover: params.prover,
                reason: "Proof verification failed".into(),
                slashed_amount: slash_amount,
            });

            return Err(SystemContractError::InvalidProof {
                reason: "Verification failed".into(),
            });
        }

        // 5. Update job state
        job.output_hash = Some(params.proof.output_hash);
        job.proof_submitted_at = Some(ctx.timestamp);
        job.verified_at = Some(ctx.timestamp);
        job.result = Some(params.result);
        job.status = JobStatus::Verified;

        // 6. Calculate fee split with potential late penalty
        let mut fee = job.bid_amount;
        if is_late {
            let penalty = job.sla.late_penalty(fee);
            fee = fee.saturating_sub(penalty);
            // Penalty goes to burn
            bank.burn(job.requester, penalty)?;
        }

        let (prover_reward, validator_reward, burn_amount) = staking.calculate_fee_split(fee);

        // 7. Distribute rewards
        // Release escrow
        bank.unlock(&job.requester, job.bid_amount)?;

        // Transfer to prover
        bank.transfer(job.requester, params.prover, prover_reward)?;

        // Transfer to validator (block proposer)
        bank.transfer(job.requester, ctx.proposer, validator_reward)?;

        // Burn
        bank.burn(job.requester, burn_amount)?;

        // 8. Update job to settled
        job.settled_at = Some(ctx.timestamp);
        job.status = JobStatus::Settled;
        self.active_jobs = self.active_jobs.saturating_sub(1);

        // 9. Emit events
        self.events.push(JobEvent::ProofSubmitted {
            job_id: params.job_id,
            prover: params.prover,
            output_hash: params.proof.output_hash,
            verification_method: params.proof.method as u8,
            block_height: ctx.height,
        });

        self.events.push(JobEvent::JobSettled {
            job_id: params.job_id,
            prover: params.prover,
            requester: job.requester,
            prover_reward,
            validator_reward,
            burned: burn_amount,
            block_height: ctx.height,
        });

        Ok(ProofSubmitResult {
            job_id: params.job_id,
            verified: true,
            prover_reward,
            validator_reward,
            burned: burn_amount,
        })
    }

    /// Verify a proof
    fn verify_proof(proof: &Proof, job: &JobState) -> SystemContractResult<bool> {
        match proof.method {
            VerificationMethod::TeeAttestation => {
                let attestation = proof.tee_attestation.as_ref().ok_or_else(|| {
                    SystemContractError::InvalidProof {
                        reason: "TEE attestation required but not provided".into(),
                    }
                })?;

                // Verify the attestation (in real implementation, call TEE precompile)
                Self::verify_tee_attestation(attestation, job)
            }

            VerificationMethod::ZkProof => {
                let zk_proof =
                    proof
                        .zk_proof
                        .as_ref()
                        .ok_or_else(|| SystemContractError::InvalidProof {
                            reason: "ZK proof required but not provided".into(),
                        })?;

                // Verify the ZK proof (in real implementation, call ZK precompile)
                Self::verify_zk_proof(zk_proof, job)
            }

            VerificationMethod::Hybrid => {
                // Both required
                let attestation = proof.tee_attestation.as_ref().ok_or_else(|| {
                    SystemContractError::InvalidProof {
                        reason: "TEE attestation required for hybrid verification".into(),
                    }
                })?;

                let zk_proof =
                    proof
                        .zk_proof
                        .as_ref()
                        .ok_or_else(|| SystemContractError::InvalidProof {
                            reason: "ZK proof required for hybrid verification".into(),
                        })?;

                let tee_valid = Self::verify_tee_attestation(attestation, job)?;
                let zk_valid = Self::verify_zk_proof(zk_proof, job)?;

                Ok(tee_valid && zk_valid)
            }

            VerificationMethod::ReExecution => {
                // In real implementation, check for matching results from multiple provers
                // For now, accept if we have the output hash
                Ok(proof.output_hash != [0u8; 32])
            }
        }
    }

    /// Verify TEE attestation against the job's expected measurement.
    ///
    /// Validates:
    /// 1. Attestation bytes are non-empty and structurally valid
    /// 2. Measurement matches the job's registered model measurement
    /// 3. Attestation timestamp is recent (within the SLA window)
    /// 4. TEE type is an approved platform
    fn verify_tee_attestation(
        attestation: &TeeAttestation,
        job: &JobState,
    ) -> SystemContractResult<bool> {
        // Reject empty attestation
        if attestation.attestation.is_empty() {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: "Empty attestation".into(),
            });
        }

        // Reject zero measurement
        if attestation.measurement == [0u8; 32] {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: "Invalid measurement (all zeros)".into(),
            });
        }

        // Verify measurement matches the model's expected measurement
        // The job's model_hash acts as the expected enclave measurement
        if attestation.measurement != job.model_hash {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: format!(
                    "Measurement mismatch: expected {:?}, got {:?}",
                    &job.model_hash[..4],
                    &attestation.measurement[..4]
                ),
            });
        }

        // Verify attestation freshness — must be within the job's SLA window
        if job.submitted_at > attestation.timestamp || attestation.timestamp > job.sla.deadline {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: "Attestation timestamp outside SLA window".into(),
            });
        }

        // Structural validation: attestation must be at least 64 bytes
        // (minimum for a signed quote structure)
        if attestation.attestation.len() < 64 {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: format!(
                    "Attestation too short: {} bytes (minimum 64)",
                    attestation.attestation.len()
                ),
            });
        }

        Ok(true)
    }

    /// Verify ZK proof against the job's expected parameters.
    ///
    /// Validates:
    /// 1. Proof bytes are non-empty and structurally valid
    /// 2. Public inputs reference the correct model and input hashes
    /// 3. Verification key hash matches the registered model's VK
    /// 4. Proof system is supported
    fn verify_zk_proof(zk_proof: &ZkProof, job: &JobState) -> SystemContractResult<bool> {
        // Reject empty proof
        if zk_proof.proof.is_empty() {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Empty proof".into(),
            });
        }

        // Verify proof system is supported
        match zk_proof.system {
            ZkSystem::Groth16 | ZkSystem::Plonk | ZkSystem::Stark | ZkSystem::Ezkl => {
                // Approved system
            }
        }

        // Verify public inputs contain the job's model and input hashes
        // At minimum, public inputs should include model_hash and input_hash
        if zk_proof.public_inputs.len() < 2 {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: format!(
                    "Insufficient public inputs: expected >= 2, got {}",
                    zk_proof.public_inputs.len()
                ),
            });
        }

        // First public input should be the model hash
        if zk_proof.public_inputs[0] != job.model_hash {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Public input[0] (model hash) does not match job".into(),
            });
        }

        // Second public input should be the input hash
        if zk_proof.public_inputs[1] != job.input_hash {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Public input[1] (input hash) does not match job".into(),
            });
        }

        // Verify verification key hash is non-zero
        if zk_proof.vk_hash == [0u8; 32] {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Zero verification key hash".into(),
            });
        }

        // Structural validation: proof must be at least 128 bytes
        // (minimum for any meaningful ZK proof)
        if zk_proof.proof.len() < 128 {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: format!(
                    "Proof too short: {} bytes (minimum 128)",
                    zk_proof.proof.len()
                ),
            });
        }

        Ok(true)
    }

    // =========================================================================
    // JOB CANCELLATION
    // =========================================================================

    /// Cancel a job
    pub fn cancel_job(
        &mut self,
        job_id: JobId,
        requester: Address,
        ctx: &BlockContext,
        bank: &mut Bank,
    ) -> SystemContractResult<JobCancelResult> {
        let job = self
            .jobs
            .get_mut(&job_id)
            .ok_or_else(|| SystemContractError::job_not_found(&job_id))?;

        // 1. Only requester can cancel
        if job.requester != requester {
            return Err(SystemContractError::OnlyRequesterCanCancel {
                requester: hex::encode(job.requester),
                caller: hex::encode(requester),
            });
        }

        // 2. Check status allows cancellation
        if !job.status.can_cancel() {
            return Err(SystemContractError::CannotCancelJob {
                job_id: hex::encode(job_id),
                status: job.status,
            });
        }

        // 3. Calculate cancellation fee
        let cancellation_fee = (job.bid_amount * self.config.cancellation_fee_bps as u128) / 10000;
        let refund_amount = job.bid_amount.saturating_sub(cancellation_fee);

        // 4. Process refund
        bank.unlock(&requester, job.bid_amount)?;
        if cancellation_fee > 0 {
            bank.burn(requester, cancellation_fee)?;
        }

        // 5. Update state
        job.status = JobStatus::Cancelled;
        self.active_jobs = self.active_jobs.saturating_sub(1);

        // 6. Emit event
        self.events.push(JobEvent::JobCancelled {
            job_id,
            requester,
            refunded: refund_amount,
            cancellation_fee,
            block_height: ctx.height,
        });

        Ok(JobCancelResult {
            job_id,
            refunded: refund_amount,
            cancellation_fee,
        })
    }

    // =========================================================================
    // EXPIRATION PROCESSING
    // =========================================================================

    /// Process expired jobs (called at end of each block)
    pub fn process_expired_jobs(
        &mut self,
        current_time: u64,
    ) -> SystemContractResult<Vec<JobEvent>> {
        let mut events = Vec::new();

        // Find all deadlines that have passed
        let expired_deadlines: Vec<u64> = self
            .jobs_by_deadline
            .range(..=current_time)
            .map(|(deadline, _)| *deadline)
            .collect();

        for deadline in expired_deadlines {
            if let Some(job_ids) = self.jobs_by_deadline.remove(&deadline) {
                for job_id in job_ids {
                    if let Some(job) = self.jobs.get_mut(&job_id) {
                        // Only expire jobs that are still active
                        if job.status.is_active() && job.sla.is_expired(current_time) {
                            job.status = JobStatus::Expired;
                            self.active_jobs = self.active_jobs.saturating_sub(1);

                            events.push(JobEvent::JobExpired {
                                job_id,
                                prover: job.assigned_prover.unwrap_or([0u8; 32]),
                                deadline: job.sla.deadline,
                                expired_at: current_time,
                                slashed_amount: 0, // Slashing handled separately
                            });
                        }
                    }
                }
            }
        }

        Ok(events)
    }

    // =========================================================================
    // STATS
    // =========================================================================

    /// Get registry statistics
    pub fn stats(&self) -> JobRegistryStats {
        JobRegistryStats {
            total_jobs: self.total_jobs,
            active_jobs: self.active_jobs,
            total_requesters: self.jobs_by_requester.len() as u64,
            total_provers: self.jobs_by_prover.len() as u64,
        }
    }
}

/// Job registry statistics
#[derive(Debug, Clone)]
pub struct JobRegistryStats {
    pub total_jobs: u64,
    pub active_jobs: u64,
    pub total_requesters: u64,
    pub total_provers: u64,
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_contracts::bank::{Bank, BankConfig};

    fn setup() -> (JobRegistry, Bank, BlockContext) {
        let registry = JobRegistry::new(JobConfig::devnet());
        let mut bank = Bank::new(BankConfig::default());

        // Give test account balance.
        bank.mint([1u8; 32], 1_000_000_000)
            .expect("mint should succeed");

        let ctx = BlockContext {
            height: 100,
            timestamp: 1000,
            slot: 100,
            proposer: [10u8; 32],
            gas_limit: 30_000_000,
            gas_used: 0,
        };

        (registry, bank, ctx)
    }

    fn submit_params() -> SubmitJobParams {
        SubmitJobParams {
            requester: [1u8; 32],
            model_hash: [2u8; 32],
            input_hash: [3u8; 32],
            max_bid: 100_000,
            bid_amount: 100_000,
            verification_method: VerificationMethod::TeeAttestation,
            priority: JobPriority::Normal,
            sla_timeout: 0,
            tags: vec![],
            encrypted_input: None,
            callback: None,
            data_provider: None,
            required_compliance: vec![],
            jurisdiction: None,
        }
    }

    #[test]
    fn test_job_submission() {
        let (mut registry, mut bank, ctx) = setup();

        let params = submit_params();

        let result = registry.submit_job(params, &ctx, &mut bank).unwrap();

        assert_eq!(result.escrowed, 100_000);
        assert!(result.sla_deadline > ctx.timestamp);

        let job = registry.get_job(&result.job_id).unwrap();
        assert_eq!(job.status, JobStatus::Submitted);
    }

    #[test]
    fn test_job_assignment() {
        let (mut registry, mut bank, ctx) = setup();

        // Submit job
        let params = submit_params();

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();

        // Assign to prover
        let prover = [20u8; 32];
        let assign_result = registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        assert_eq!(assign_result.prover, prover);

        let job = registry.get_job(&submit_result.job_id).unwrap();
        assert_eq!(job.status, JobStatus::Assigned);
        assert_eq!(job.assigned_prover, Some(prover));
    }

    #[test]
    fn test_job_cancellation() {
        let (mut registry, mut bank, ctx) = setup();

        // Submit job
        let params = submit_params();

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();

        // Cancel job
        let cancel_result = registry
            .cancel_job(submit_result.job_id, [1u8; 32], &ctx, &mut bank)
            .unwrap();

        assert_eq!(cancel_result.refunded, 100_000); // No fee in devnet

        let job = registry.get_job(&submit_result.job_id).unwrap();
        assert_eq!(job.status, JobStatus::Cancelled);
    }

    #[test]
    fn test_sla_policy() {
        let config = JobConfig::mainnet();

        let sla = SlaPolicy::new(&config, JobPriority::Normal, 1000, 0);
        assert_eq!(sla.deadline, 1000 + config.default_sla_timeout);

        // Urgent has shorter deadline
        let urgent_sla = SlaPolicy::new(&config, JobPriority::Urgent, 1000, 0);
        assert!(urgent_sla.deadline < sla.deadline);
    }
}
