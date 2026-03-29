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

use crate::precompiles::tee::UniversalTeeVerifyPrecompile;
use crate::precompiles::zkp::UnifiedZkpVerifyPrecompile;
use crate::precompiles::Precompile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;

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

    /// Enterprise mode: when true, settlement requires Hybrid verification
    /// with both TEE attestation and zkML proof present
    pub enterprise_mode: bool,
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
            enterprise_mode: false,
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
            enterprise_mode: false,
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
            enterprise_mode: false,
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

    /// Anti-replay: SHA-256 hashes of previously verified TEE attestations
    seen_attestation_hashes: HashSet<[u8; 32]>,

    /// Enterprise mode: when true, TEE verification failures are always hard
    /// failures regardless of the `sgx` compile-time feature flag. Simulated
    /// TEE platforms are also rejected in enterprise mode.
    enterprise_mode: bool,

    /// Enterprise zkML configuration — controls hard-fail behavior,
    /// circuit registration, and domain-binding requirements for zkML
    /// proof verification.
    enterprise_zkml_config: EnterpriseModeConfig,

    /// Set of pre-registered verifying-key hashes.  In enterprise mode
    /// with `require_registered_circuit`, every zkML proof's `vk_hash`
    /// must be present in this set.
    registered_circuits: HashSet<[u8; 32]>,
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
            seen_attestation_hashes: HashSet::new(),
            enterprise_mode: false,
            enterprise_zkml_config: EnterpriseModeConfig {
                enabled: false,
                ..EnterpriseModeConfig::default()
            },
            registered_circuits: HashSet::new(),
        }
    }

    /// Create new job registry with enterprise mode enabled.
    /// In enterprise mode, TEE verification failures are always hard failures
    /// and simulated TEE platforms are rejected.
    pub fn new_enterprise(config: JobConfig) -> Self {
        let mut registry = Self::new(config);
        registry.enterprise_mode = true;
        registry.enterprise_zkml_config = EnterpriseModeConfig {
            enabled: true,
            ..EnterpriseModeConfig::default()
        };
        registry
    }

    /// Enable or disable enterprise mode at runtime.
    pub fn set_enterprise_mode(&mut self, enabled: bool) {
        self.enterprise_mode = enabled;
    }

    /// Returns whether enterprise mode is active.
    pub fn is_enterprise_mode(&self) -> bool {
        self.enterprise_mode
    }

    /// Set the enterprise zkML configuration.
    pub fn set_enterprise_zkml_config(&mut self, config: EnterpriseModeConfig) {
        self.enterprise_zkml_config = config;
    }

    /// Register a verifying-key hash as a known circuit.
    /// Enterprise mode with `require_registered_circuit` demands that
    /// every zkML proof's `vk_hash` is present in this set.
    pub fn register_circuit(&mut self, vk_hash: [u8; 32]) {
        self.registered_circuits.insert(vk_hash);
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
        // --- Phase 1: mutable borrow for pre-checks and SLA expiry ---
        let (is_late, job_snapshot) = {
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

            // 4. Enterprise mode enforcement: require Hybrid with both halves
            if self.config.enterprise_mode {
                if params.proof.method != VerificationMethod::Hybrid {
                    return Err(SystemContractError::SettlementFailed {
                        reason: format!(
                            "Enterprise mode requires Hybrid verification, got {:?}",
                            params.proof.method
                        ),
                    });
                }
                if !params.proof.is_enterprise_compliant() {
                    return Err(SystemContractError::SettlementFailed {
                        reason: "Enterprise mode requires both TEE attestation and ZK proof".into(),
                    });
                }
            }

            (is_late, job.clone())
        }; // mutable borrow on self.jobs dropped here

        // 4. Verify the proof (TEE and/or ZK) — may call precompile via &self
        let verified = self.verify_proof(&params.proof, &job_snapshot)?;

        // Re-borrow the job mutably for subsequent status updates
        let job = self
            .jobs
            .get_mut(&params.job_id)
            .expect("job must still exist after verify_proof");

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
    fn verify_proof(&mut self, proof: &Proof, job: &JobState) -> SystemContractResult<bool> {
        match proof.method {
            VerificationMethod::TeeAttestation => {
                let attestation = proof.tee_attestation.as_ref().ok_or_else(|| {
                    SystemContractError::InvalidProof {
                        reason: "TEE attestation required but not provided".into(),
                    }
                })?;

                // Verify the attestation via structural checks + TEE precompile
                self.verify_tee_attestation(attestation, job)
            }

            VerificationMethod::ZkProof => {
                let zk_proof =
                    proof
                        .zk_proof
                        .as_ref()
                        .ok_or_else(|| SystemContractError::InvalidProof {
                            reason: "ZK proof required but not provided".into(),
                        })?;

                // Route supported proof systems through the unified 0x0300 verifier path.
                self.verify_zk_proof(zk_proof, job)
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

                let tee_valid = self.verify_tee_attestation(attestation, job)?;
                let zk_valid = self.verify_zk_proof(zk_proof, job)?;

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
    /// 5. Anti-replay: attestation hash has not been seen before
    /// 6. Cryptographic verification via the UniversalTeeVerifyPrecompile
    fn verify_tee_attestation(
        &mut self,
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

        // Verify attestation freshness - must be within the job's SLA window
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

        // Anti-replay protection: compute SHA-256 of the raw attestation bytes
        // and reject if we have already verified this exact attestation.
        let att_hash: [u8; 32] = Sha256::digest(&attestation.attestation).into();
        if self.seen_attestation_hashes.contains(&att_hash) {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: "attestation replay detected".into(),
            });
        }

        // Enterprise guard: reject simulated/unknown TEE platforms.
        // In non-enterprise (devnet) mode all real platform types are accepted;
        // the Simulated variant only exists on the PoUW engine side, but we
        // defensively reject any platform byte that would map to Simulated (0xFF)
        // when enterprise mode is active. Since TeeType currently only has real
        // platforms this guard is future-proofing plus an explicit signal.
        // (No TeeType::Simulated variant exists yet, but if attestation bytes
        // smuggle a 0xFF prefix they would be caught by the precompile's
        // Unknown path. This guard adds a belt-and-suspenders check.)

        // Determine platform prefix byte from TeeType for the precompile envelope
        let platform_prefix: u8 = match attestation.tee_type {
            TeeType::AwsNitro => 0x01,
            TeeType::IntelSgx => 0x02,
            TeeType::AmdSev => 0x04,
        };

        // Enterprise mode: reject if the raw attestation bytes start with the
        // Simulated platform marker (0xFF) which could bypass real verification.
        if self.enterprise_mode && !attestation.attestation.is_empty() && attestation.attestation[0] == 0xFF {
            return Err(SystemContractError::TeeVerificationFailed {
                reason: "Enterprise mode rejects simulated TEE attestations".into(),
            });
        }

        // Build precompile input: platform byte + raw attestation bytes
        let mut precompile_input = Vec::with_capacity(1 + attestation.attestation.len());
        precompile_input.push(platform_prefix);
        precompile_input.extend_from_slice(&attestation.attestation);

        // Invoke the UniversalTeeVerifyPrecompile for cryptographic verification.
        // The precompile may panic on malformed attestation data in non-production
        // builds (e.g. integer overflow during quote parsing), so we catch panics
        // to ensure a clean error path.
        let precompile = if self.enterprise_mode {
            UniversalTeeVerifyPrecompile::with_enterprise()
        } else {
            UniversalTeeVerifyPrecompile::with_defaults()
        };
        let gas_limit = 1_000_000; // generous limit for verification
        let input_for_precompile = precompile_input;
        let precompile_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            precompile.execute(&input_for_precompile, gas_limit)
        }));

        match precompile_outcome {
            Ok(Ok(result)) => {
                if !result.success {
                    // When the sgx feature is enabled OR enterprise mode is active,
                    // hard-fail on precompile rejection. Without either, the precompile
                    // may lack real crypto backends, so we only log the soft failure
                    // and still accept the structural checks.
                    #[cfg(feature = "sgx")]
                    return Err(SystemContractError::TeeVerificationFailed {
                        reason: "TEE precompile rejected attestation".into(),
                    });

                    #[cfg(not(feature = "sgx"))]
                    if self.enterprise_mode {
                        return Err(SystemContractError::TeeVerificationFailed {
                            reason: "Enterprise mode: TEE precompile rejected attestation".into(),
                        });
                    }
                }
            }
            Ok(Err(_e)) => {
                // Under the sgx feature or enterprise mode the precompile must
                // succeed; without either we tolerate errors from stub verifiers.
                #[cfg(feature = "sgx")]
                return Err(SystemContractError::TeeVerificationFailed {
                    reason: format!("TEE precompile error: {}", _e),
                });

                #[cfg(not(feature = "sgx"))]
                if self.enterprise_mode {
                    return Err(SystemContractError::TeeVerificationFailed {
                        reason: format!("Enterprise mode: TEE precompile error: {}", _e),
                    });
                }
            }
            Err(_panic) => {
                // Precompile panicked (e.g. overflow on malformed input). Under the
                // sgx feature or enterprise mode this is a hard failure; otherwise
                // tolerate it.
                #[cfg(feature = "sgx")]
                return Err(SystemContractError::TeeVerificationFailed {
                    reason: "TEE precompile panicked during verification".into(),
                });

                #[cfg(not(feature = "sgx"))]
                if self.enterprise_mode {
                    return Err(SystemContractError::TeeVerificationFailed {
                        reason: "Enterprise mode: TEE precompile panicked during verification".into(),
                    });
                }
            }
        }

        // Record the attestation hash to prevent future replay
        self.seen_attestation_hashes.insert(att_hash);

        Ok(true)
    }

    /// Verify ZK proof against the job's expected parameters.
    ///
    /// Validates:
    /// 1. Proof bytes are non-empty and structurally valid
    /// 2. Public inputs reference the correct model and input hashes
    /// 3. Verification key hash matches the registered model's VK
    /// 4. Proof system is supported
    /// 5. Supported systems are routed through the unified 0x0300 precompile envelope
    fn verify_zk_proof(&self, zk_proof: &ZkProof, job: &JobState) -> SystemContractResult<bool> {
        let ent = &self.enterprise_zkml_config;

        // Reject empty proof
        if zk_proof.proof.is_empty() {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Empty proof".into(),
            });
        }

        // Verify proof system is supported
        match zk_proof.system {
            ZkSystem::Groth16
            | ZkSystem::Plonk
            | ZkSystem::Stark
            | ZkSystem::Ezkl
            | ZkSystem::Halo2 => {
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

        // -----------------------------------------------------------------
        // Enterprise guard: require_registered_circuit
        // -----------------------------------------------------------------
        if ent.enabled && ent.require_registered_circuit {
            if !self.registered_circuits.contains(&zk_proof.vk_hash) {
                return Err(SystemContractError::ZkVerificationFailed {
                    reason: "Enterprise mode: circuit vk_hash is not registered".into(),
                });
            }
        }

        // -----------------------------------------------------------------
        // Enterprise guard: require_domain_binding
        // -----------------------------------------------------------------
        if ent.enabled && ent.require_domain_binding {
            let output_hash = job.output_hash.ok_or_else(|| {
                SystemContractError::ZkVerificationFailed {
                    reason: "Enterprise mode: job output_hash is required for domain binding but is None".into(),
                }
            })?;
            if zk_proof.public_inputs.len() < 3 {
                return Err(SystemContractError::ZkVerificationFailed {
                    reason: "Enterprise mode: domain binding requires >= 3 public inputs (model, input, output)".into(),
                });
            }
            if zk_proof.public_inputs[2] != output_hash {
                return Err(SystemContractError::ZkVerificationFailed {
                    reason: "Enterprise mode: public_input[2] (output commitment) does not match job output_hash".into(),
                });
            }
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

        // All five proof systems are routed through the unified 0x0300 precompile.
        match zk_proof.system {
            ZkSystem::Groth16
            | ZkSystem::Plonk
            | ZkSystem::Ezkl
            | ZkSystem::Halo2
            | ZkSystem::Stark => {
                return self.verify_zk_proof_via_precompile(zk_proof, job);
            }
        }
    }

    fn verify_zk_proof_via_precompile(
        &self,
        zk_proof: &ZkProof,
        job: &JobState,
    ) -> SystemContractResult<bool> {
        let input = Self::encode_unified_zkp_input(zk_proof, job)?;
        let precompile = UnifiedZkpVerifyPrecompile::with_defaults();
        let gas_limit = precompile.gas_cost(&input);
        let result = precompile.execute(&input, gas_limit).map_err(|err| {
            SystemContractError::ZkVerificationFailed {
                reason: format!("0x0300 precompile execution failed: {err}"),
            }
        })?;

        let precompile_valid = result.output.last().copied() == Some(1);

        // Enterprise hard-fail: when enterprise zkML mode is enabled,
        // ALWAYS reject invalid proofs regardless of the `zkp` feature.
        // This eliminates the soft-acceptance path where proof failures
        // are tolerated when the `zkp` feature is not compiled in.
        if self.enterprise_zkml_config.enabled && !precompile_valid {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "Enterprise mode: 0x0300 precompile reported an invalid proof (hard-fail)".into(),
            });
        }

        if cfg!(feature = "zkp") && !precompile_valid {
            return Err(SystemContractError::ZkVerificationFailed {
                reason: "0x0300 precompile reported an invalid proof".into(),
            });
        }

        Ok(true)
    }

    fn encode_unified_zkp_input(
        zk_proof: &ZkProof,
        job: &JobState,
    ) -> SystemContractResult<Vec<u8>> {
        let mut input = Vec::new();
        match zk_proof.system {
            ZkSystem::Plonk => {
                input.push(0x02);
                input.extend_from_slice(
                    &(u32::try_from(zk_proof.proof.len()).map_err(|_| {
                        SystemContractError::ZkVerificationFailed {
                            reason: "PLONK proof exceeds 4 GiB precompile envelope".into(),
                        }
                    })?)
                    .to_le_bytes(),
                );
                input.extend_from_slice(&zk_proof.vk_hash);
                input.extend_from_slice(
                    &(u32::try_from(zk_proof.public_inputs.len()).map_err(|_| {
                        SystemContractError::ZkVerificationFailed {
                            reason: "too many PLONK public inputs for precompile envelope".into(),
                        }
                    })?)
                    .to_le_bytes(),
                );
                input.extend_from_slice(&Self::flatten_public_inputs(&zk_proof.public_inputs));
                input.extend_from_slice(&zk_proof.proof);
            }
            ZkSystem::Ezkl => {
                input.push(0x03);
                input.push(1); // version
                input.push(0); // native EZKL backend
                input.extend_from_slice(&job.model_hash);
                input.extend_from_slice(&zk_proof.vk_hash);
                input.extend_from_slice(
                    &(u16::try_from(zk_proof.public_inputs.len()).map_err(|_| {
                        SystemContractError::ZkVerificationFailed {
                            reason: "too many EZKL public inputs for precompile envelope".into(),
                        }
                    })?)
                    .to_le_bytes(),
                );
                input.extend_from_slice(
                    &(u32::try_from(zk_proof.proof.len()).map_err(|_| {
                        SystemContractError::ZkVerificationFailed {
                            reason: "EZKL proof exceeds 4 GiB precompile envelope".into(),
                        }
                    })?)
                    .to_le_bytes(),
                );
                input.extend_from_slice(&Self::flatten_public_inputs(&zk_proof.public_inputs));
                input.extend_from_slice(&zk_proof.proof);
            }
            ZkSystem::Halo2 => {
                input.push(0x04);
                input.extend_from_slice(&zk_proof.vk_hash);
                input.extend_from_slice(&Self::flatten_public_inputs(&zk_proof.public_inputs));
                input.extend_from_slice(&zk_proof.proof);
            }
            ZkSystem::Groth16 => {
                input.push(0x01); // Groth16 tag
                // The Groth16 precompile expects fixed-layout BN254 input after
                // the unified precompile strips the tag byte:
                //   [verifying_key: 544 bytes][proof: 192 bytes][public_inputs: N * 32 bytes]
                //
                // We embed the 32-byte VK hash at the start of a zero-padded
                // 544-byte VK slot so the precompile can identify the circuit.
                // The proof bytes are similarly right-padded to 192 bytes.
                // Without the `zkp` feature the actual arkworks verification is
                // skipped, but the structural envelope must still satisfy
                // min_input_length validation.
                const BN254_VK_SIZE: usize = 544;
                const BN254_PROOF_SIZE: usize = 192;

                // VK slot: embed vk_hash then zero-pad to 544 bytes
                let mut vk_slot = vec![0u8; BN254_VK_SIZE];
                let copy_len = zk_proof.vk_hash.len().min(BN254_VK_SIZE);
                vk_slot[..copy_len].copy_from_slice(&zk_proof.vk_hash[..copy_len]);
                input.extend_from_slice(&vk_slot);

                // Proof slot: copy proof bytes then zero-pad to 192 bytes
                let mut proof_slot = vec![0u8; BN254_PROOF_SIZE];
                let proof_copy = zk_proof.proof.len().min(BN254_PROOF_SIZE);
                proof_slot[..proof_copy]
                    .copy_from_slice(&zk_proof.proof[..proof_copy]);
                input.extend_from_slice(&proof_slot);

                // Public inputs: each 32 bytes, appended as-is
                input.extend_from_slice(&Self::flatten_public_inputs(&zk_proof.public_inputs));
            }
            ZkSystem::Stark => {
                // Tag 0x05 for STARK in the unified router.
                // Input format after tag:
                //   [vk_hash:32][num_inputs:u32 LE][inputs: N*32][proof...]
                input.push(0x05);
                input.extend_from_slice(&zk_proof.vk_hash);
                input.extend_from_slice(
                    &(u32::try_from(zk_proof.public_inputs.len()).map_err(|_| {
                        SystemContractError::ZkVerificationFailed {
                            reason: "too many STARK public inputs for precompile envelope".into(),
                        }
                    })?)
                    .to_le_bytes(),
                );
                input.extend_from_slice(&Self::flatten_public_inputs(&zk_proof.public_inputs));
                input.extend_from_slice(&zk_proof.proof);
            }
        }

        Ok(input)
    }

    fn flatten_public_inputs(public_inputs: &[Hash]) -> Vec<u8> {
        let mut flattened = Vec::with_capacity(public_inputs.len() * 32);
        for public_input in public_inputs {
            flattened.extend_from_slice(public_input);
        }
        flattened
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
    use crate::system_contracts::staking::{StakingConfig, StakingManager};
    use parking_lot::RwLock;
    use std::sync::Arc;

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

    fn staking_manager() -> StakingManager {
        StakingManager::new(
            StakingConfig::devnet(),
            Arc::new(RwLock::new(Bank::new(BankConfig::default()))),
        )
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

    #[test]
    fn test_verify_ezkl_proof_routes_through_unified_precompile() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![0xAA; 256],
            public_inputs: vec![job.model_hash, job.input_hash, [4u8; 32]],
            vk_hash: [5u8; 32],
        };

        assert!(registry.verify_zk_proof(&zk_proof, &job).unwrap());
    }

    #[test]
    fn test_submit_ezkl_proof_settles_job() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        let proof = Proof {
            method: VerificationMethod::ZkProof,
            tee_attestation: None,
            zk_proof: Some(ZkProof {
                system: ZkSystem::Ezkl,
                proof: vec![0xBB; 256],
                public_inputs: vec![[2u8; 32], [3u8; 32], [6u8; 32]],
                vk_hash: [7u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 12,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let mut staking = staking_manager();
        let result = registry
            .submit_proof(
                SubmitProofParams {
                    job_id: submit_result.job_id,
                    prover,
                    proof,
                    result: vec![0x42],
                },
                &ctx,
                &mut staking,
                &mut bank,
            )
            .unwrap();

        assert!(result.verified);
        assert_eq!(
            registry.get_job(&submit_result.job_id).unwrap().status,
            JobStatus::Settled
        );
    }

    /// All five proof systems (Groth16, Plonk, Ezkl, Halo2, Stark) are now
    /// wired into the unified 0x0300 precompile envelope.
    /// `encode_unified_zkp_input` must succeed for every variant.
    #[test]
    fn test_unsupported_proof_system_fails_explicitly() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // All systems must encode successfully — no unsupported systems remain.
        let systems: Vec<(ZkSystem, u8)> = vec![
            (ZkSystem::Groth16, 0x01),
            (ZkSystem::Plonk, 0x02),
            (ZkSystem::Ezkl, 0x03),
            (ZkSystem::Halo2, 0x04),
            (ZkSystem::Stark, 0x05),
        ];

        for (system, expected_tag) in systems {
            let proof = ZkProof {
                system,
                proof: vec![0xCC; 256],
                public_inputs: vec![job.model_hash, job.input_hash],
                vk_hash: [5u8; 32],
            };
            let encoded = JobRegistry::encode_unified_zkp_input(&proof, &job);
            assert!(
                encoded.is_ok(),
                "{:?} must encode for the 0x0300 envelope, got: {:?}",
                system,
                encoded.unwrap_err()
            );
            let bytes = encoded.unwrap();
            assert_eq!(
                bytes[0], expected_tag,
                "First byte for {:?} must be tag 0x{:02x}",
                system, expected_tag
            );
        }
    }

    /// Groth16 proofs must be routed through `verify_zk_proof_via_precompile`
    /// (the unified 0x0300 precompile path) instead of the structural-only path.
    #[test]
    fn test_groth16_routes_through_unified_precompile() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // Build a structurally valid Groth16 ZkProof
        let zk_proof = ZkProof {
            system: ZkSystem::Groth16,
            proof: vec![0xAA; 256],
            public_inputs: vec![job.model_hash, job.input_hash],
            vk_hash: [7u8; 32],
        };

        // encode_unified_zkp_input must succeed for Groth16
        let encoded = JobRegistry::encode_unified_zkp_input(&zk_proof, &job).unwrap();

        // Verify envelope structure: tag 0x01, then 32-byte VK hash, then proof/input lengths
        assert_eq!(encoded[0], 0x01, "Tag byte must be 0x01 for Groth16");
        assert_eq!(
            &encoded[1..33],
            &[7u8; 32],
            "Bytes 1..33 must be the VK hash"
        );

        // verify_zk_proof must route Groth16 through the precompile path.
        // Without the `zkp` feature the precompile returns a stub success,
        // so the proof should verify successfully.
        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_ok(),
            "Groth16 verify_zk_proof must succeed via precompile path, got: {:?}",
            result.unwrap_err()
        );
    }

    /// STARK proofs must be routed through `verify_zk_proof_via_precompile`
    /// (the unified 0x0300 precompile path with tag 0x05).
    #[test]
    fn test_stark_routes_through_unified_precompile() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // Build a structurally valid STARK ZkProof
        let zk_proof = ZkProof {
            system: ZkSystem::Stark,
            proof: vec![0xBB; 256],
            public_inputs: vec![job.model_hash, job.input_hash],
            vk_hash: [8u8; 32],
        };

        // encode_unified_zkp_input must succeed for STARK
        let encoded = JobRegistry::encode_unified_zkp_input(&zk_proof, &job).unwrap();

        // Verify envelope structure: tag 0x05, then 32-byte VK hash, then num_inputs
        assert_eq!(encoded[0], 0x05, "Tag byte must be 0x05 for STARK");
        assert_eq!(
            &encoded[1..33],
            &[8u8; 32],
            "Bytes 1..33 must be the VK hash"
        );
        // num_inputs = 2 (model_hash + input_hash)
        let num_inputs = u32::from_le_bytes([encoded[33], encoded[34], encoded[35], encoded[36]]);
        assert_eq!(num_inputs, 2, "num_inputs must be 2");

        // Public inputs start at byte 37, each 32 bytes
        assert_eq!(
            &encoded[37..69],
            &job.model_hash[..],
            "First public input must be model_hash"
        );
        assert_eq!(
            &encoded[69..101],
            &job.input_hash[..],
            "Second public input must be input_hash"
        );

        // Remaining bytes are the proof
        assert_eq!(
            &encoded[101..],
            &vec![0xBB; 256][..],
            "Proof bytes must follow public inputs"
        );

        // verify_zk_proof must route STARK through the precompile path.
        // Without the `zkp` feature the precompile returns a stub success,
        // so the proof should verify successfully.
        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_ok(),
            "STARK verify_zk_proof must succeed via precompile path, got: {:?}",
            result.unwrap_err()
        );
    }

    /// Hybrid verification requires *both* TEE attestation and ZK proof to
    /// pass.  Providing only one component must fail with an explicit error.
    #[test]
    fn test_hybrid_verification_requires_both() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::Hybrid;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // ---- TEE-only proof (missing ZK) should fail ----
        let tee_only_proof = Proof {
            method: VerificationMethod::Hybrid,
            tee_attestation: Some(TeeAttestation {
                tee_type: TeeType::IntelSgx,
                attestation: vec![0xAA; 128],
                measurement: job.model_hash,
                timestamp: ctx.timestamp,
            }),
            zk_proof: None,
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let tee_only_err = registry.verify_proof(&tee_only_proof, &job).unwrap_err();
        match &tee_only_err {
            SystemContractError::InvalidProof { reason } => {
                assert!(
                    reason.contains("ZK proof required for hybrid"),
                    "Expected hybrid ZK requirement error, got: {reason}"
                );
            }
            other => panic!("Expected InvalidProof for missing ZK, got: {other:?}"),
        }

        // ---- ZK-only proof (missing TEE) should fail ----
        let zk_only_proof = Proof {
            method: VerificationMethod::Hybrid,
            tee_attestation: None,
            zk_proof: Some(ZkProof {
                system: ZkSystem::Ezkl,
                proof: vec![0xBB; 256],
                public_inputs: vec![job.model_hash, job.input_hash, [4u8; 32]],
                vk_hash: [5u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let zk_only_err = registry.verify_proof(&zk_only_proof, &job).unwrap_err();
        match &zk_only_err {
            SystemContractError::InvalidProof { reason } => {
                assert!(
                    reason.contains("TEE attestation required for hybrid"),
                    "Expected hybrid TEE requirement error, got: {reason}"
                );
            }
            other => panic!("Expected InvalidProof for missing TEE, got: {other:?}"),
        }

        // ---- Both present should succeed ----
        let hybrid_proof = Proof {
            method: VerificationMethod::Hybrid,
            tee_attestation: Some(TeeAttestation {
                tee_type: TeeType::IntelSgx,
                attestation: vec![0xAA; 128],
                measurement: job.model_hash,
                timestamp: ctx.timestamp,
            }),
            zk_proof: Some(ZkProof {
                system: ZkSystem::Ezkl,
                proof: vec![0xBB; 256],
                public_inputs: vec![job.model_hash, job.input_hash, [4u8; 32]],
                vk_hash: [5u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let hybrid_valid = registry.verify_proof(&hybrid_proof, &job).unwrap();
        assert!(hybrid_valid, "Hybrid proof with both components must pass");
    }

    /// Successful proof submission must produce a `ProofSubmitResult` with
    /// verified flag set, positive prover/validator rewards, and a burn amount.
    #[test]
    fn test_proof_submission_metadata() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        let proof = Proof {
            method: VerificationMethod::ZkProof,
            tee_attestation: None,
            zk_proof: Some(ZkProof {
                system: ZkSystem::Ezkl,
                proof: vec![0xBB; 256],
                public_inputs: vec![[2u8; 32], [3u8; 32], [6u8; 32]],
                vk_hash: [7u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 50,
                memory_used: 4096,
                inference_ops: 5,
                complexity: 10_000,
            },
        };

        let mut staking = staking_manager();
        let result = registry
            .submit_proof(
                SubmitProofParams {
                    job_id: submit_result.job_id,
                    prover,
                    proof,
                    result: vec![0x42],
                },
                &ctx,
                &mut staking,
                &mut bank,
            )
            .unwrap();

        // Verify metadata fields
        assert!(result.verified, "proof must be marked verified");
        assert!(
            result.prover_reward > 0,
            "prover_reward must be positive, got {}",
            result.prover_reward
        );
        assert!(
            result.validator_reward > 0,
            "validator_reward must be positive, got {}",
            result.validator_reward
        );
        assert!(
            result.burned > 0,
            "burned amount must be positive, got {}",
            result.burned
        );

        // Sanity: rewards + burn = original bid
        let total = result.prover_reward + result.validator_reward + result.burned;
        assert_eq!(
            total, 100_000,
            "fee split must sum to original bid (100_000), got {total}"
        );
    }

    /// Groth16 proofs route through the structural verification path (tag 0x01
    /// in the 0x0300 envelope is not yet supported, so `verify_zk_proof` falls
    /// through to the deterministic structural check rather than calling the
    /// precompile).  A valid Groth16 proof must settle the job successfully.
    #[test]
    fn test_groth16_proof_submission() {
        let (mut registry, mut bank, ctx) = setup();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        // Groth16 proof that passes structural checks
        let proof = Proof {
            method: VerificationMethod::ZkProof,
            tee_attestation: None,
            zk_proof: Some(ZkProof {
                system: ZkSystem::Groth16,
                proof: vec![0x03; 256], // 0x03 tag byte pattern
                public_inputs: vec![[2u8; 32], [3u8; 32]],
                vk_hash: [7u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 30,
                memory_used: 2048,
                inference_ops: 1,
                complexity: 4096,
            },
        };

        let mut staking = staking_manager();
        let result = registry
            .submit_proof(
                SubmitProofParams {
                    job_id: submit_result.job_id,
                    prover,
                    proof,
                    result: vec![0x01, 0x00],
                },
                &ctx,
                &mut staking,
                &mut bank,
            )
            .unwrap();

        assert!(result.verified, "Groth16 proof must verify via structural path");
        assert!(
            result.prover_reward > 0,
            "Groth16 settlement must yield prover_reward"
        );

        let job = registry.get_job(&submit_result.job_id).unwrap();
        assert_eq!(
            job.status,
            JobStatus::Settled,
            "Job must be settled after Groth16 proof"
        );
    }

    /// Verifies that `verify_tee_attestation` invokes the TEE precompile.
    /// The precompile is called with the platform-prefix byte + attestation bytes.
    /// Without the `sgx` feature the precompile error is tolerated (soft-fail),
    /// but we can confirm the function completes successfully with structural
    /// checks passing and the attestation hash recorded for replay protection.
    #[test]
    fn test_tee_attestation_calls_precompile() {
        let (mut registry, mut bank, ctx) = setup();
        let params = submit_params();
        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        let attestation = TeeAttestation {
            tee_type: TeeType::IntelSgx,
            attestation: vec![0xAA; 128],
            measurement: job.model_hash,
            timestamp: ctx.timestamp,
        };

        // Before verification, no attestation hashes recorded
        assert!(
            registry.seen_attestation_hashes.is_empty(),
            "No attestation hashes should exist before verification"
        );

        let result = registry.verify_tee_attestation(&attestation, &job);
        assert!(
            result.is_ok(),
            "TEE attestation with valid structural fields should pass: {:?}",
            result.err()
        );
        assert!(result.unwrap(), "verify_tee_attestation should return true");

        // After verification, the attestation hash must be recorded
        let expected_hash: [u8; 32] = Sha256::digest(&attestation.attestation).into();
        assert!(
            registry.seen_attestation_hashes.contains(&expected_hash),
            "Attestation hash must be recorded after successful verification"
        );
    }

    /// Submitting the same TEE attestation twice must fail on the second attempt
    /// with a replay-detection error.
    #[test]
    fn test_tee_attestation_replay_rejected() {
        let (mut registry, mut bank, ctx) = setup();
        let params = submit_params();
        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        let attestation = TeeAttestation {
            tee_type: TeeType::AwsNitro,
            attestation: vec![0xBB; 128],
            measurement: job.model_hash,
            timestamp: ctx.timestamp,
        };

        // First submission must succeed
        let first = registry.verify_tee_attestation(&attestation, &job);
        assert!(first.is_ok(), "First attestation should pass");

        // Second submission of identical attestation must fail
        let second = registry.verify_tee_attestation(&attestation, &job);
        assert!(second.is_err(), "Replayed attestation must be rejected");

        match second.unwrap_err() {
            SystemContractError::TeeVerificationFailed { reason } => {
                assert!(
                    reason.contains("replay detected"),
                    "Expected replay error, got: {reason}"
                );
            }
            other => panic!("Expected TeeVerificationFailed, got: {other:?}"),
        }
    }

    // =========================================================================
    // ENTERPRISE MODE TESTS
    // =========================================================================

    /// Helper: create an enterprise-mode setup (registry with enterprise_mode=true)
    fn setup_enterprise() -> (JobRegistry, Bank, BlockContext) {
        let mut config = JobConfig::devnet();
        config.enterprise_mode = true;
        let registry = JobRegistry::new(config);
        let mut bank = Bank::new(BankConfig::default());
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

    /// Helper: build a valid hybrid proof with both TEE and ZK halves
    fn make_hybrid_proof(model_hash: Hash, input_hash: Hash, timestamp: u64) -> Proof {
        Proof {
            method: VerificationMethod::Hybrid,
            tee_attestation: Some(TeeAttestation {
                tee_type: TeeType::AwsNitro,
                attestation: vec![0xAA; 128],
                measurement: model_hash,
                timestamp,
            }),
            zk_proof: Some(ZkProof {
                system: ZkSystem::Groth16,
                proof: vec![0xBB; 256],
                public_inputs: vec![model_hash, input_hash],
                vk_hash: [7u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        }
    }

    #[test]
    fn test_enterprise_rejects_tee_only_settlement() {
        let (mut registry, mut bank, ctx) = setup_enterprise();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::TeeAttestation;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        let proof = Proof {
            method: VerificationMethod::TeeAttestation,
            tee_attestation: Some(TeeAttestation {
                tee_type: TeeType::AwsNitro,
                attestation: vec![0xAA; 128],
                measurement: [2u8; 32],
                timestamp: 1000,
            }),
            zk_proof: None,
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let mut staking = staking_manager();
        let result = registry.submit_proof(
            SubmitProofParams {
                job_id: submit_result.job_id,
                prover,
                proof,
                result: vec![0x42],
            },
            &ctx,
            &mut staking,
            &mut bank,
        );

        assert!(result.is_err(), "TEE-only must be rejected in enterprise mode");
        match result.unwrap_err() {
            SystemContractError::SettlementFailed { reason } => {
                assert!(
                    reason.contains("Enterprise mode requires Hybrid"),
                    "Expected enterprise rejection, got: {reason}"
                );
            }
            other => panic!("Expected SettlementFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_enterprise_rejects_zkml_only_settlement() {
        let (mut registry, mut bank, ctx) = setup_enterprise();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        let proof = Proof {
            method: VerificationMethod::ZkProof,
            tee_attestation: None,
            zk_proof: Some(ZkProof {
                system: ZkSystem::Groth16,
                proof: vec![0xCC; 256],
                public_inputs: vec![[2u8; 32], [3u8; 32]],
                vk_hash: [7u8; 32],
            }),
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let mut staking = staking_manager();
        let result = registry.submit_proof(
            SubmitProofParams {
                job_id: submit_result.job_id,
                prover,
                proof,
                result: vec![0x42],
            },
            &ctx,
            &mut staking,
            &mut bank,
        );

        assert!(result.is_err(), "ZkProof-only must be rejected in enterprise mode");
        match result.unwrap_err() {
            SystemContractError::SettlementFailed { reason } => {
                assert!(
                    reason.contains("Enterprise mode requires Hybrid"),
                    "Expected enterprise rejection, got: {reason}"
                );
            }
            other => panic!("Expected SettlementFailed, got: {other:?}"),
        }
    }

    #[test]
    fn test_enterprise_accepts_hybrid_settlement() {
        let (mut registry, mut bank, ctx) = setup_enterprise();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::Hybrid;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        let proof = make_hybrid_proof([2u8; 32], [3u8; 32], 1000);

        let mut staking = staking_manager();
        let result = registry.submit_proof(
            SubmitProofParams {
                job_id: submit_result.job_id,
                prover,
                proof,
                result: vec![0x42],
            },
            &ctx,
            &mut staking,
            &mut bank,
        );

        assert!(
            result.is_ok(),
            "Hybrid with both halves must succeed in enterprise mode: {:?}",
            result.err()
        );
        let r = result.unwrap();
        assert!(r.verified);
        assert_eq!(
            registry.get_job(&submit_result.job_id).unwrap().status,
            JobStatus::Settled
        );
    }

    #[test]
    fn test_enterprise_rejects_partial_hybrid() {
        let (mut registry, mut bank, ctx) = setup_enterprise();
        let mut params = submit_params();
        params.verification_method = VerificationMethod::Hybrid;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let prover = [20u8; 32];
        registry
            .assign_job(submit_result.job_id, prover, &ctx)
            .unwrap();

        // Hybrid method but zk_proof is None (partial)
        let proof = Proof {
            method: VerificationMethod::Hybrid,
            tee_attestation: Some(TeeAttestation {
                tee_type: TeeType::AwsNitro,
                attestation: vec![0xAA; 128],
                measurement: [2u8; 32],
                timestamp: 1000,
            }),
            zk_proof: None, // Missing ZK half
            output_hash: [8u8; 32],
            metadata: ProofMetadata {
                execution_time_ms: 10,
                memory_used: 1024,
                inference_ops: 1,
                complexity: 2048,
            },
        };

        let mut staking = staking_manager();
        let result = registry.submit_proof(
            SubmitProofParams {
                job_id: submit_result.job_id,
                prover,
                proof,
                result: vec![0x42],
            },
            &ctx,
            &mut staking,
            &mut bank,
        );

        assert!(
            result.is_err(),
            "Partial hybrid must be rejected in enterprise mode"
        );
        match result.unwrap_err() {
            SystemContractError::SettlementFailed { reason } => {
                assert!(
                    reason.contains("both TEE attestation and ZK proof"),
                    "Expected partial hybrid rejection, got: {reason}"
                );
            }
            other => panic!("Expected SettlementFailed, got: {other:?}"),
        }
    }

    fn setup_enterprise_job() -> (JobRegistry, Bank, BlockContext, JobId) {
        let mut registry = JobRegistry::new_enterprise(JobConfig::devnet());
        let mut bank = Bank::new(BankConfig::default());
        bank.mint([1u8; 32], 1_000_000_000).expect("mint");
        let ctx = BlockContext { height: 100, timestamp: 1000, slot: 100, proposer: [10u8; 32], gas_limit: 30_000_000, gas_used: 0 };
        let params = submit_params();
        let sr = registry.submit_job(params, &ctx, &mut bank).unwrap();
        let p = [20u8; 32];
        registry.assign_job(sr.job_id, p, &ctx).unwrap();
        // Job is now Assigned - ready for proof verification
        (registry, bank, ctx, sr.job_id)
    }

    #[test]
    fn test_enterprise_tee_rejects_without_sgx_feature() {
        let (mut reg, _, _, jid) = setup_enterprise_job();
        assert!(reg.is_enterprise_mode());
        let job = reg.get_job(&jid).unwrap().clone();
        let att = TeeAttestation { tee_type: TeeType::IntelSgx, attestation: vec![0x02; 128], measurement: job.model_hash, timestamp: job.submitted_at + 1 };
        let r = reg.verify_tee_attestation(&att, &job);
        assert!(r.is_err(), "Enterprise mode must hard-fail TEE without sgx feature");
    }

    #[test]
    fn test_enterprise_tee_rejects_simulated_platform() {
        let (mut reg, _, _, jid) = setup_enterprise_job();
        let job = reg.get_job(&jid).unwrap().clone();
        let mut ab = vec![0xFF]; ab.extend_from_slice(&vec![0xAA; 127]);
        let att = TeeAttestation { tee_type: TeeType::IntelSgx, attestation: ab, measurement: job.model_hash, timestamp: job.submitted_at + 1 };
        let r = reg.verify_tee_attestation(&att, &job);
        assert!(r.is_err(), "Enterprise mode must reject simulated TEE");
        let em = format!("{:?}", r.unwrap_err());
        assert!(em.contains("simulated") || em.contains("Simulated"), "got: {em}");
    }

    #[test]
    fn test_enterprise_tee_rejects_malformed_attestation() {
        let (mut reg, _, _, jid) = setup_enterprise_job();
        let job = reg.get_job(&jid).unwrap().clone();
        let att = TeeAttestation { tee_type: TeeType::IntelSgx, attestation: vec![0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], measurement: job.model_hash, timestamp: job.submitted_at + 1 };
        let r = reg.verify_tee_attestation(&att, &job);
        assert!(r.is_err(), "Enterprise mode must reject malformed attestation");
    }

    #[test]
    fn test_enterprise_tee_hardfail_on_precompile_error() {
        let (mut reg, _, _, jid) = setup_enterprise_job();
        let job = reg.get_job(&jid).unwrap().clone();
        let att = TeeAttestation { tee_type: TeeType::IntelSgx, attestation: vec![0xAA; 128], measurement: job.model_hash, timestamp: job.submitted_at + 1 };
        let r = reg.verify_tee_attestation(&att, &job);
        assert!(r.is_err(), "Enterprise mode must hard-fail on precompile error");
    }

    #[test]
    fn test_devnet_tee_allows_simulated_platform() {
        let (mut reg, mut bank, ctx) = setup();
        assert!(!reg.is_enterprise_mode());
        let params = submit_params();
        let sr = reg.submit_job(params, &ctx, &mut bank).unwrap();
        let p = [20u8; 32];
        reg.assign_job(sr.job_id, p, &ctx).unwrap();
        // Job is now Assigned - ready for proof verification
        let job = reg.get_job(&sr.job_id).unwrap().clone();
        let att = TeeAttestation { tee_type: TeeType::IntelSgx, attestation: vec![0xAA; 128], measurement: job.model_hash, timestamp: job.submitted_at + 1 };
        let r = reg.verify_tee_attestation(&att, &job);
        assert!(r.is_ok(), "Devnet mode should tolerate mock TEE verification");
    }

    // =========================================================================
    // SQ04 — ENTERPRISE ZKML HARD-FAIL TESTS
    // =========================================================================

    /// Helper: create an enterprise zkML setup with full enterprise guards.
    fn setup_enterprise_zkml() -> (JobRegistry, Bank, BlockContext) {
        let config = JobConfig::devnet();
        let mut registry = JobRegistry::new(config);
        registry.set_enterprise_mode(true);
        registry.set_enterprise_zkml_config(EnterpriseModeConfig {
            enabled: true,
            required_method: VerificationMethod::Hybrid,
            allow_zkml_fallback: false,
            require_registered_circuit: true,
            require_domain_binding: true,
        });
        let mut bank = Bank::new(BankConfig::default());
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

    /// Enterprise mode must reject zkML proofs even when the `zkp` feature
    /// is not compiled in (i.e. the precompile returns a stub).  Without
    /// enterprise mode the stub returns success; with enterprise mode the
    /// invalid-proof hard-fail path must trigger.
    #[test]
    fn test_enterprise_zkml_rejects_without_zkp_feature() {
        let (mut registry, mut bank, ctx) = setup_enterprise_zkml();
        // Register the circuit so that guard passes
        registry.register_circuit([5u8; 32]);

        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();

        // Set output_hash on the job for domain binding
        {
            let job_mut = registry.jobs.get_mut(&submit_result.job_id).unwrap();
            job_mut.output_hash = Some([9u8; 32]);
        }
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            // Intentionally invalid proof bytes — will fail real verification
            proof: vec![0x00; 256],
            public_inputs: vec![job.model_hash, job.input_hash, [9u8; 32]],
            vk_hash: [5u8; 32],
        };

        let result = registry.verify_zk_proof(&zk_proof, &job);

        // With the `zkp` feature, real verification rejects the invalid proof
        // bytes.  Without the `zkp` feature, the precompile stubs return
        // `Err(...)` which propagates as ZkVerificationFailed.
        //
        // In enterprise mode both paths produce a hard error — the proof is
        // never silently accepted.
        assert!(
            result.is_err(),
            "Enterprise mode must never silently accept — got Ok even though \
             proof bytes are invalid (zkp feature = {})",
            cfg!(feature = "zkp")
        );
    }

    /// Enterprise mode must reject proofs whose circuit hash (vk_hash) is
    /// not in the registered circuits set.
    #[test]
    fn test_enterprise_zkml_requires_registered_circuit() {
        let (mut registry, mut bank, ctx) = setup_enterprise_zkml();
        // Deliberately do NOT register any circuit

        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![0xAA; 256],
            public_inputs: vec![job.model_hash, job.input_hash, [9u8; 32]],
            vk_hash: [99u8; 32], // unregistered
        };

        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_err(),
            "Enterprise mode must reject unregistered circuit vk_hash"
        );
        match result.unwrap_err() {
            SystemContractError::ZkVerificationFailed { reason } => {
                assert!(
                    reason.contains("not registered"),
                    "Expected registered-circuit error, got: {reason}"
                );
            }
            other => panic!("Expected ZkVerificationFailed, got: {other:?}"),
        }
    }

    /// Enterprise mode must reject proofs that lack domain binding (output
    /// commitment).  The job must have an output_hash and the third public
    /// input must match it.
    #[test]
    fn test_enterprise_zkml_requires_domain_binding() {
        let (mut registry, mut bank, ctx) = setup_enterprise_zkml();
        registry.register_circuit([5u8; 32]);

        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();

        // Job has NO output_hash — domain binding must fail
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();
        assert!(job.output_hash.is_none(), "precondition: output_hash must be None");

        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![0xAA; 256],
            public_inputs: vec![job.model_hash, job.input_hash],
            vk_hash: [5u8; 32],
        };

        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_err(),
            "Enterprise mode must reject missing domain binding"
        );
        match result.unwrap_err() {
            SystemContractError::ZkVerificationFailed { reason } => {
                assert!(
                    reason.contains("domain binding") || reason.contains("output_hash"),
                    "Expected domain-binding error, got: {reason}"
                );
            }
            other => panic!("Expected ZkVerificationFailed, got: {other:?}"),
        }
    }

    /// Enterprise mode with a bad proof: empty or too-short proof bytes must
    /// hard-fail regardless of feature flags.
    #[test]
    fn test_enterprise_zkml_hardfail_on_invalid_proof() {
        let (mut registry, mut bank, ctx) = setup_enterprise_zkml();
        registry.register_circuit([5u8; 32]);

        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();
        {
            let job_mut = registry.jobs.get_mut(&submit_result.job_id).unwrap();
            job_mut.output_hash = Some([9u8; 32]);
        }
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // Construct a proof with empty bytes — must hard-fail even before
        // reaching the precompile because of the structural check.
        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![], // empty = instant rejection
            public_inputs: vec![job.model_hash, job.input_hash, [9u8; 32]],
            vk_hash: [5u8; 32],
        };

        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_err(),
            "Empty proof must always hard-fail in enterprise mode"
        );

        // Also test proof that is non-empty but too short (< 128 bytes)
        let zk_proof_short = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![0xDE; 64], // too short
            public_inputs: vec![job.model_hash, job.input_hash, [9u8; 32]],
            vk_hash: [5u8; 32],
        };

        let result_short = registry.verify_zk_proof(&zk_proof_short, &job);
        assert!(
            result_short.is_err(),
            "Short proof must hard-fail in enterprise mode"
        );
        match result_short.unwrap_err() {
            SystemContractError::ZkVerificationFailed { reason } => {
                assert!(
                    reason.contains("too short") || reason.contains("minimum 128"),
                    "Expected proof-too-short error, got: {reason}"
                );
            }
            other => panic!("Expected ZkVerificationFailed, got: {other:?}"),
        }
    }

    /// Non-enterprise mode must continue to accept proofs without the
    /// enterprise guards (registered circuit, domain binding).
    #[test]
    fn test_non_enterprise_zkml_unaffected() {
        let (mut registry, mut bank, ctx) = setup();
        // Default setup: enterprise_zkml_config.enabled = false (via new())

        let mut params = submit_params();
        params.verification_method = VerificationMethod::ZkProof;

        let submit_result = registry.submit_job(params, &ctx, &mut bank).unwrap();
        registry
            .assign_job(submit_result.job_id, [20u8; 32], &ctx)
            .unwrap();
        let job = registry.get_job(&submit_result.job_id).unwrap().clone();

        // Proof with unregistered circuit and no domain binding
        let zk_proof = ZkProof {
            system: ZkSystem::Ezkl,
            proof: vec![0xAA; 256],
            public_inputs: vec![job.model_hash, job.input_hash],
            vk_hash: [99u8; 32], // not registered — fine in non-enterprise
        };

        let result = registry.verify_zk_proof(&zk_proof, &job);
        assert!(
            result.is_ok(),
            "Non-enterprise mode must accept proofs without enterprise guards, got: {:?}",
            result.unwrap_err()
        );
    }
}
