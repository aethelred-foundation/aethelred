# Consensus Mechanism: Proof of Useful Work (PoUW)

<p align="center">
  <strong>Aethelred Consensus Layer Technical Specification</strong><br/>
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
| **Last Updated** | 2026-02-08 |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [The Problem with Traditional Consensus](#2-the-problem-with-traditional-consensus)
3. [Proof of Useful Work Architecture](#3-proof-of-useful-work-architecture)
4. [Validator Selection Algorithm](#4-validator-selection-algorithm)
5. [Compute Job Verification](#5-compute-job-verification)
6. [Block Production Flow](#6-block-production-flow)
7. [Slashing Conditions](#7-slashing-conditions)
8. [Economic Security](#8-economic-security)
9. [Implementation Details](#9-implementation-details)
10. [Performance Analysis](#10-performance-analysis)

---

## 1. Introduction

### 1.1 What is Proof of Useful Work?

**Proof of Useful Work (PoUW)** is Aethelred's novel consensus mechanism that replaces wasteful cryptographic puzzles with productive AI computation. Instead of validators competing to solve meaningless SHA-256 hashes (Bitcoin) or simply staking tokens (Ethereum), Aethelred validators perform **real AI inference jobs** that generate value for the network.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONSENSUS MECHANISM COMPARISON                            │
├────────────────┬────────────────┬────────────────┬───────────────────────────┤
│                │ Proof of Work  │ Proof of Stake │ Proof of Useful Work      │
├────────────────┼────────────────┼────────────────┼───────────────────────────┤
│ Security       │ Hash power     │ Staked tokens  │ Stake + Hardware + Work   │
│ Energy Usage   │ Enormous       │ Minimal        │ Productive (AI inference) │
│ Centralization │ Mining pools   │ Wealth         │ Hardware capabilities     │
│ Output Value   │ Zero           │ Zero           │ Verified AI outputs       │
│ Finality       │ Probabilistic  │ Fast           │ Instant (CometBFT)        │
│ Hardware       │ ASICs          │ Generic        │ TEE + GPU (specialized)   │
└────────────────┴────────────────┴────────────────┴───────────────────────────┘
```

### 1.2 Design Goals

| Goal | Description | Implementation |
|------|-------------|----------------|
| **Productive Energy** | Every joule spent on consensus generates useful output | AI inference as block production work |
| **Cryptographic Verification** | Prove computation correctness without re-execution | TEE attestation + optional ZK proofs |
| **Decentralization** | Prevent hardware centralization | Multiple TEE vendors, diverse hardware |
| **Instant Finality** | No waiting for confirmations | CometBFT Byzantine fault tolerance |
| **Sovereignty** | Respect data jurisdiction | Geographic validator routing |

### 1.3 Key Innovation: The 80/20 Split

Traditional blockchains waste 100% of their computational energy on consensus overhead. Aethelred inverts this ratio:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPUTE ALLOCATION                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   TRADITIONAL BLOCKCHAIN                                                     │
│   ┌────────────────────────────────────────────────────────────────────┐    │
│   │████████████████████████████████████████████████████████████████████│    │
│   │                     100% CONSENSUS OVERHEAD                        │    │
│   │                     (SHA-256, ECDSA verify)                        │    │
│   └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│   AETHELRED (PoUW)                                                          │
│   ┌───────────────────────────────────────────────────────────┬────────┐    │
│   │███████████████████████████████████████████████████████████│▓▓▓▓▓▓▓▓│    │
│   │                   80% USEFUL WORK                         │   20%  │    │
│   │                   (AI Inference)                          │Consensus│   │
│   └───────────────────────────────────────────────────────────┴────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The Problem with Traditional Consensus

### 2.1 Proof of Work Limitations

Bitcoin's Proof of Work creates an adversarial game where miners compete to find hash collisions. This has three fundamental problems:

1. **Energy Waste**: ~150 TWh/year (more than Argentina) produces no useful output
2. **Centralization**: ASIC manufacturing concentrated in few hands
3. **Environmental Impact**: Carbon footprint larger than many nations

### 2.2 Proof of Stake Limitations

Ethereum's Proof of Stake addresses energy waste but introduces new issues:

1. **Capital Barriers**: 32 ETH (~$100K+) to become a validator
2. **Wealth Concentration**: Rich get richer through staking rewards
3. **Nothing-at-Stake**: Theoretical attack vectors in chain splits
4. **No Productive Output**: Staked capital sits idle

### 2.3 The Aethelred Solution

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROOF OF USEFUL WORK ADVANTAGES                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ✓ ENERGY EFFICIENCY                                                        │
│    Every watt generates valuable AI inferences, not hash collisions         │
│                                                                              │
│  ✓ HARDWARE DECENTRALIZATION                                                │
│    Multiple TEE vendors (Intel, AMD, AWS, NVIDIA) prevent monopoly          │
│                                                                              │
│  ✓ PRODUCTIVE OUTPUT                                                        │
│    Block production directly serves customer compute requests               │
│                                                                              │
│  ✓ INSTANT FINALITY                                                         │
│    CometBFT provides immediate, irreversible block confirmation             │
│                                                                              │
│  ✓ CRYPTOGRAPHIC GUARANTEES                                                 │
│    TEE attestation + ZK proofs ensure computation correctness               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Proof of Useful Work Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    PROOF OF USEFUL WORK ARCHITECTURE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                            ┌───────────────┐                                │
│                            │  USER REQUEST │                                │
│                            │  (AI Job)     │                                │
│                            └───────┬───────┘                                │
│                                    │                                         │
│                                    ▼                                         │
│                          ┌─────────────────┐                                │
│                          │  USEFUL WORK    │                                │
│                          │     ROUTER      │                                │
│                          └────────┬────────┘                                │
│                                   │                                          │
│          ┌────────────────────────┼────────────────────────┐                │
│          │                        │                        │                │
│          ▼                        ▼                        ▼                │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐         │
│   │  VALIDATOR A │        │  VALIDATOR B │        │  VALIDATOR C │         │
│   │   (UAE)      │        │    (EU)      │        │    (US)      │         │
│   │              │        │              │        │              │         │
│   │  ┌────────┐  │        │  ┌────────┐  │        │  ┌────────┐  │         │
│   │  │  TEE   │  │        │  │  TEE   │  │        │  │  TEE   │  │         │
│   │  │ H100   │  │        │  │ H100   │  │        │  │ H100   │  │         │
│   │  └────────┘  │        │  └────────┘  │        │  └────────┘  │         │
│   └──────┬───────┘        └──────┬───────┘        └──────┬───────┘         │
│          │                       │                       │                  │
│          └───────────────────────┼───────────────────────┘                  │
│                                  │                                          │
│                                  ▼                                          │
│                        ┌─────────────────┐                                  │
│                        │    CONSENSUS    │                                  │
│                        │   (CometBFT)    │                                  │
│                        └────────┬────────┘                                  │
│                                 │                                           │
│                                 ▼                                           │
│                        ┌─────────────────┐                                  │
│                        │  DIGITAL SEAL   │                                  │
│                        │   (On-Chain)    │                                  │
│                        └─────────────────┘                                  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Component Details

#### 3.2.1 Useful Work Router

The Useful Work Router is the intelligent job allocation system that matches compute requests to appropriate validators.

```rust
/// Useful Work Router - Job Allocation Engine
pub struct UsefulWorkRouter {
    /// Validator registry with capabilities
    validators: ValidatorRegistry,

    /// Pending job queue (priority ordered)
    job_queue: PriorityQueue<ComputeJob>,

    /// Load balancer state
    load_balancer: LoadBalancer,

    /// Jurisdiction routing table
    jurisdiction_map: JurisdictionMap,

    /// Hardware capability index
    hardware_index: HardwareIndex,
}

impl UsefulWorkRouter {
    /// Route a compute job to the optimal validator
    pub fn route_job(&self, job: &ComputeJob) -> Result<ValidatorAssignment, RoutingError> {
        // Step 1: Filter by jurisdiction requirements
        let candidates = self.filter_by_jurisdiction(&job.jurisdiction)?;

        // Step 2: Filter by hardware requirements
        let candidates = self.filter_by_hardware(candidates, &job.hardware_req)?;

        // Step 3: Filter by model support
        let candidates = self.filter_by_model(candidates, &job.model_id)?;

        // Step 4: Select optimal validator based on:
        //   - Current load (lower is better)
        //   - Reputation score (higher is better)
        //   - Latency to user (lower is better)
        //   - Price (if variable pricing enabled)
        let selected = self.select_optimal(candidates, &job)?;

        // Step 5: Create binding commitment
        let commitment = self.create_commitment(&job, &selected)?;

        Ok(ValidatorAssignment {
            validator: selected,
            commitment,
            deadline: job.deadline,
            collateral: job.fee * 2, // 2x fee as collateral
        })
    }
}
```

#### 3.2.2 Validator TEE Environment

Each validator runs a Trusted Execution Environment that provides hardware-level isolation for AI inference.

```rust
/// Validator TEE Execution Environment
pub struct ValidatorTEE {
    /// Hardware type (SGX, SEV-SNP, Nitro, H100 CC)
    hardware: HardwareType,

    /// Attestation service connection
    attestation: AttestationService,

    /// Encrypted model storage
    model_vault: ModelVault,

    /// Secure memory region
    enclave: EnclaveMemory,

    /// Execution metrics
    metrics: ExecutionMetrics,
}

impl ValidatorTEE {
    /// Execute a compute job within the TEE
    pub fn execute_job(&mut self, job: EncryptedJob) -> Result<JobResult, ExecutionError> {
        // Step 1: Verify job signature
        job.verify_signature()?;

        // Step 2: Generate fresh attestation
        let attestation = self.attestation.generate()?;

        // Step 3: Load model into enclave
        let model = self.model_vault.load(&job.model_id)?;
        self.enclave.load_model(model)?;

        // Step 4: Decrypt input data using sealed keys
        let input = self.enclave.decrypt(&job.encrypted_input)?;

        // Step 5: Execute inference
        let start = Instant::now();
        let output = self.enclave.infer(&input)?;
        let duration = start.elapsed();

        // Step 6: Encrypt output for user
        let encrypted_output = self.enclave.encrypt_for(&output, &job.user_pubkey)?;

        // Step 7: Generate execution proof
        let proof = ExecutionProof {
            attestation,
            input_hash: blake3::hash(&input),
            output_hash: blake3::hash(&output),
            model_hash: model.hash(),
            duration,
            timestamp: Utc::now(),
        };

        // Step 8: Sign result
        let signature = self.enclave.sign(&proof)?;

        Ok(JobResult {
            job_id: job.id,
            encrypted_output,
            proof,
            signature,
        })
    }
}
```

### 3.3 Consensus Integration (ABCI++)

Aethelred uses CometBFT's ABCI++ interface to integrate Proof of Useful Work into the consensus process.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ABCI++ CONSENSUS FLOW                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    1. EXTEND_VOTE                                    │    │
│  │                                                                      │    │
│  │  During each consensus round, validators include their completed     │    │
│  │  compute jobs as Vote Extensions:                                   │    │
│  │                                                                      │    │
│  │  VoteExtension {                                                    │    │
│  │      validator_addr: "aethval1abc...",                              │    │
│  │      completed_jobs: [                                              │    │
│  │          JobResult { job_id, proof, signature },                    │    │
│  │          JobResult { job_id, proof, signature },                    │    │
│  │      ],                                                             │    │
│  │      attestation: TEEAttestation { ... },                           │    │
│  │  }                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    2. VERIFY_VOTE_EXTENSION                          │    │
│  │                                                                      │    │
│  │  Other validators verify the Vote Extensions:                       │    │
│  │                                                                      │    │
│  │  • Validate TEE attestation signature chain                         │    │
│  │  • Verify job completion proofs                                     │    │
│  │  • Check output commitments match                                   │    │
│  │  • Ensure jurisdiction compliance                                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    3. PREPARE_PROPOSAL                               │    │
│  │                                                                      │    │
│  │  Block proposer aggregates valid Vote Extensions:                   │    │
│  │                                                                      │    │
│  │  • Collect all verified job results                                 │    │
│  │  • Calculate validator rewards                                      │    │
│  │  • Determine fee burns                                              │    │
│  │  • Create Digital Seals                                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    4. PROCESS_PROPOSAL                               │    │
│  │                                                                      │    │
│  │  All validators verify the proposed block:                          │    │
│  │                                                                      │    │
│  │  • Re-verify all job results                                        │    │
│  │  • Check reward calculations                                        │    │
│  │  • Validate state transitions                                       │    │
│  │  • Accept or reject proposal                                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                    5. FINALIZE_BLOCK                                 │    │
│  │                                                                      │    │
│  │  Upon 2/3+1 consensus:                                              │    │
│  │                                                                      │    │
│  │  • Block committed to chain                                         │    │
│  │  • Rewards distributed                                              │    │
│  │  • Fees burned                                                      │    │
│  │  • Digital Seals finalized                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Validator Selection Algorithm

### 4.1 Selection Criteria

Validators are selected for compute jobs based on a multi-dimensional scoring function:

```rust
/// Validator Selection Score
pub struct SelectionScore {
    /// Base score from stake (logarithmic to prevent whale dominance)
    pub stake_score: f64,

    /// Hardware capability score
    pub hardware_score: f64,

    /// Historical performance score (SLA compliance)
    pub performance_score: f64,

    /// Geographic compliance score
    pub jurisdiction_score: f64,

    /// Current load factor (inverse - lower load = higher score)
    pub load_score: f64,

    /// Randomness component (VRF-based)
    pub randomness: f64,
}

impl SelectionScore {
    /// Calculate composite selection score
    pub fn composite(&self) -> f64 {
        // Weighted combination of factors
        const STAKE_WEIGHT: f64 = 0.20;       // 20% stake
        const HARDWARE_WEIGHT: f64 = 0.25;    // 25% hardware capability
        const PERFORMANCE_WEIGHT: f64 = 0.25; // 25% past performance
        const JURISDICTION_WEIGHT: f64 = 0.10; // 10% jurisdiction match
        const LOAD_WEIGHT: f64 = 0.10;        // 10% current load
        const RANDOM_WEIGHT: f64 = 0.10;      // 10% randomness

        (self.stake_score * STAKE_WEIGHT)
            + (self.hardware_score * HARDWARE_WEIGHT)
            + (self.performance_score * PERFORMANCE_WEIGHT)
            + (self.jurisdiction_score * JURISDICTION_WEIGHT)
            + (self.load_score * LOAD_WEIGHT)
            + (self.randomness * RANDOM_WEIGHT)
    }
}
```

### 4.2 Stake-Based Scoring

Unlike pure Proof of Stake, Aethelred uses **logarithmic stake scoring** to prevent whale dominance:

```rust
/// Calculate stake score with diminishing returns
pub fn calculate_stake_score(stake: u128) -> f64 {
    // Minimum stake: 100,000 AETHEL
    const MIN_STAKE: u128 = 100_000 * 10u128.pow(18);

    // Score = ln(stake / min_stake) / ln(max_observed_stake / min_stake)
    // This gives a score between 0 and 1, with diminishing returns for larger stakes

    if stake < MIN_STAKE {
        return 0.0;
    }

    // Use natural log to create diminishing returns
    let normalized_stake = (stake as f64) / (MIN_STAKE as f64);
    let log_stake = normalized_stake.ln();

    // Normalize to 0-1 range (assuming max 100M stake)
    const MAX_LOG: f64 = 6.907755; // ln(1000) - covers 1000x difference
    (log_stake / MAX_LOG).min(1.0)
}
```

**Visual Representation:**

```
Score │
  1.0 │                              ┌───────────────────
      │                         ┌────┘
  0.8 │                    ┌────┘
      │               ┌────┘
  0.6 │          ┌────┘
      │     ┌────┘
  0.4 │┌────┘
      │
  0.2 │
      │
  0.0 └──────────────────────────────────────────────────
      100K   1M     10M    50M   100M              Stake

      Logarithmic scoring prevents whale dominance
```

### 4.3 Hardware Capability Scoring

```rust
/// Hardware capability tiers
pub enum HardwareTier {
    /// Entry tier: Intel Xeon + SGX
    Tier1 { score: f64 },

    /// Standard tier: AMD EPYC + SEV-SNP
    Tier2 { score: f64 },

    /// Premium tier: NVIDIA H100 + Nitro
    Tier3 { score: f64 },

    /// Enterprise tier: Multi-GPU + Air-gapped TEE
    Tier4 { score: f64 },
}

impl HardwareTier {
    pub fn score(&self) -> f64 {
        match self {
            HardwareTier::Tier1 { .. } => 0.40,
            HardwareTier::Tier2 { .. } => 0.60,
            HardwareTier::Tier3 { .. } => 0.85,
            HardwareTier::Tier4 { .. } => 1.00,
        }
    }
}

/// Hardware capability matrix
///
/// ┌─────────────┬───────────┬──────────────┬─────────────┬───────────┐
/// │ Tier        │ TEE       │ GPU          │ Memory      │ Score     │
/// ├─────────────┼───────────┼──────────────┼─────────────┼───────────┤
/// │ Tier 1      │ SGX       │ None/T4      │ 64 GB       │ 0.40      │
/// │ Tier 2      │ SEV-SNP   │ A100 40GB    │ 128 GB      │ 0.60      │
/// │ Tier 3      │ Nitro     │ H100 80GB    │ 256 GB      │ 0.85      │
/// │ Tier 4      │ Air-gap   │ 8x H100      │ 2 TB        │ 1.00      │
/// └─────────────┴───────────┴──────────────┴─────────────┴───────────┘
```

### 4.4 VRF-Based Randomness

To prevent deterministic gaming of the selection algorithm, we include a VRF (Verifiable Random Function) component:

```rust
/// Generate verifiable random selection
pub struct VRFSelection {
    /// VRF output
    output: [u8; 32],

    /// Proof that output is correctly computed
    proof: VRFProof,

    /// Block hash used as input
    block_hash: [u8; 32],

    /// Validator's public key
    validator_pubkey: PublicKey,
}

impl VRFSelection {
    /// Generate VRF output for this round
    pub fn generate(
        secret_key: &SecretKey,
        block_hash: &[u8; 32],
    ) -> Result<Self, VRFError> {
        // VRF input = H(block_hash || round_number)
        let input = Self::compute_input(block_hash)?;

        // Generate VRF output and proof
        let (output, proof) = vrf::prove(secret_key, &input)?;

        Ok(Self {
            output,
            proof,
            block_hash: *block_hash,
            validator_pubkey: secret_key.public_key(),
        })
    }

    /// Verify VRF output
    pub fn verify(&self) -> Result<bool, VRFError> {
        let input = Self::compute_input(&self.block_hash)?;
        vrf::verify(&self.validator_pubkey, &input, &self.output, &self.proof)
    }

    /// Convert VRF output to randomness score (0.0 - 1.0)
    pub fn to_score(&self) -> f64 {
        // Interpret first 8 bytes as u64, normalize to 0-1
        let value = u64::from_le_bytes(self.output[0..8].try_into().unwrap());
        (value as f64) / (u64::MAX as f64)
    }
}
```

---

## 5. Compute Job Verification

### 5.1 Dual Verification System

Aethelred employs a dual verification system: **TEE Attestation** (fast, primary) and **Zero-Knowledge Proofs** (optional, cryptographic).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    DUAL VERIFICATION SYSTEM                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         TEE ATTESTATION                                │  │
│  │                         (Primary - Fast)                               │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  Latency: ~10ms                                                       │  │
│  │  Trust Model: Hardware manufacturer (Intel, AMD, AWS)                 │  │
│  │  Verification: Signature chain to known root keys                     │  │
│  │  Coverage: 100% of compute jobs                                       │  │
│  │                                                                        │  │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │  │
│  │  │  Hardware   │───►│ Attestation │───►│   Intel     │               │  │
│  │  │   (SGX)     │    │   Report    │    │   DCAP      │               │  │
│  │  └─────────────┘    └─────────────┘    └─────────────┘               │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                    │                                         │
│                                    ▼                                         │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                       ZERO-KNOWLEDGE PROOF                             │  │
│  │                      (Optional - Cryptographic)                        │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  Latency: 5-30 seconds                                                │  │
│  │  Trust Model: Mathematics (no hardware trust)                         │  │
│  │  Verification: SNARK/STARK verification                               │  │
│  │  Coverage: High-value or disputed jobs                                │  │
│  │                                                                        │  │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐               │  │
│  │  │ Computation │───►│    EZKL     │───►│  ZK Proof   │               │  │
│  │  │   Trace     │    │   Prover    │    │  On-Chain   │               │  │
│  │  └─────────────┘    └─────────────┘    └─────────────┘               │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 TEE Attestation Verification

```rust
/// TEE Attestation Verification
pub struct AttestationVerifier {
    /// Known root CA certificates for each vendor
    root_certs: HashMap<HardwareVendor, Certificate>,

    /// Revocation list (TCB levels, specific CPUs)
    revocation_list: RevocationList,

    /// Expected enclave measurements (MRENCLAVE, MRSIGNER)
    expected_measurements: EnclaveRegistry,
}

impl AttestationVerifier {
    /// Verify an attestation report
    pub fn verify(&self, report: &AttestationReport) -> Result<AttestationResult, VerifyError> {
        // Step 1: Verify signature chain to root CA
        let chain_valid = self.verify_signature_chain(report)?;
        if !chain_valid {
            return Err(VerifyError::InvalidSignatureChain);
        }

        // Step 2: Check TCB (Trusted Computing Base) is not revoked
        if self.revocation_list.is_revoked(&report.tcb_info) {
            return Err(VerifyError::RevokedTCB);
        }

        // Step 3: Verify enclave measurement matches expected
        let expected = self.expected_measurements.get(&report.enclave_id)?;
        if report.mr_enclave != expected.mr_enclave {
            return Err(VerifyError::MeasurementMismatch);
        }

        // Step 4: Verify timestamp is recent (within attestation window)
        const MAX_AGE: Duration = Duration::from_secs(3600); // 1 hour
        if report.timestamp.elapsed() > MAX_AGE {
            return Err(VerifyError::AttestationExpired);
        }

        // Step 5: Verify user data (job ID, output commitment)
        if !report.verify_user_data() {
            return Err(VerifyError::InvalidUserData);
        }

        Ok(AttestationResult {
            valid: true,
            hardware_vendor: report.vendor,
            tcb_level: report.tcb_info.level,
            enclave_id: report.enclave_id,
            timestamp: report.timestamp,
        })
    }
}
```

### 5.3 Zero-Knowledge Proof Verification

```rust
/// ZK-ML Proof Verification (EZKL-based)
pub struct ZKMLVerifier {
    /// Cached verifying keys for registered models
    verifying_keys: HashMap<ModelHash, VerifyingKey>,

    /// Circuit registry
    circuit_registry: CircuitRegistry,
}

impl ZKMLVerifier {
    /// Verify a ZK proof of correct ML inference
    pub fn verify(
        &self,
        model_hash: &ModelHash,
        proof: &ZKProof,
        public_inputs: &PublicInputs,
    ) -> Result<bool, ZKVerifyError> {
        // Step 1: Load verifying key for this model
        let vk = self.verifying_keys
            .get(model_hash)
            .ok_or(ZKVerifyError::UnknownModel)?;

        // Step 2: Prepare public inputs
        let inputs = vec![
            public_inputs.input_commitment,  // Hash of input
            public_inputs.output_commitment, // Hash of output
            public_inputs.model_commitment,  // Hash of model weights
        ];

        // Step 3: Verify the proof
        let valid = ezkl::verify(vk, &proof.bytes, &inputs)?;

        Ok(valid)
    }
}

/// Public inputs for ZK verification (no private data revealed)
pub struct PublicInputs {
    /// Blake3 hash of the input data
    pub input_commitment: [u8; 32],

    /// Blake3 hash of the output data
    pub output_commitment: [u8; 32],

    /// Blake3 hash of model weights
    pub model_commitment: [u8; 32],
}
```

---

## 6. Block Production Flow

### 6.1 Round Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BLOCK PRODUCTION FLOW                                │
│                         (Single Consensus Round)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  T+0.0s    PROPOSE                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Block proposer (round-robin from validator set):                    │    │
│  │  • Collects pending transactions from mempool                        │    │
│  │  • Includes completed compute job results from previous round       │    │
│  │  • Aggregates vote extensions from previous block                   │    │
│  │  • Calculates rewards and fee burns                                 │    │
│  │  • Broadcasts proposal to all validators                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│  T+0.5s    PREVOTE                 ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  All validators:                                                     │    │
│  │  • Validate proposed block                                          │    │
│  │  • Verify all compute job proofs                                    │    │
│  │  • Check state transitions                                          │    │
│  │  • Broadcast prevote (accept/reject)                                │    │
│  │  • Include vote extension with own completed jobs                   │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│  T+1.5s    PRECOMMIT               ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  If 2/3+ prevotes received:                                         │    │
│  │  • Lock on proposed block                                           │    │
│  │  • Broadcast precommit                                              │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│  T+2.5s    COMMIT                  ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  If 2/3+ precommits received:                                       │    │
│  │  • Block finalized                                                  │    │
│  │  • State transitions applied                                        │    │
│  │  • Rewards distributed                                              │    │
│  │  • Digital Seals created                                            │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│  T+3.0s    NEXT ROUND              ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  New round begins with next proposer                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Vote Extension Structure

```rust
/// Vote Extension - Carried through consensus
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoteExtension {
    /// Validator who produced this extension
    pub validator_addr: ValidatorAddress,

    /// Completed compute jobs in this round
    pub completed_jobs: Vec<CompletedJob>,

    /// Fresh TEE attestation (proves hardware is genuine)
    pub attestation: TEEAttestation,

    /// Timestamp of extension creation
    pub timestamp: DateTime<Utc>,

    /// Signature over the extension
    pub signature: Signature,
}

/// Completed compute job (included in vote extension)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletedJob {
    /// Original job ID
    pub job_id: JobId,

    /// Encrypted output (for user)
    pub encrypted_output: EncryptedBlob,

    /// Hash of plaintext output (for verification)
    pub output_commitment: Blake3Hash,

    /// Execution proof (TEE attestation + optional ZK)
    pub proof: ExecutionProof,

    /// Execution metrics
    pub metrics: ExecutionMetrics,
}

/// Execution proof combining TEE and optional ZK
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProof {
    /// TEE attestation (always present)
    pub tee_attestation: TEEAttestation,

    /// ZK proof (optional, for high-value jobs)
    pub zk_proof: Option<ZKProof>,

    /// Input commitment (hash)
    pub input_commitment: Blake3Hash,

    /// Model commitment (hash)
    pub model_commitment: Blake3Hash,

    /// Execution duration
    pub duration: Duration,
}
```

---

## 7. Slashing Conditions

### 7.1 Slashable Offenses

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SLASHING CONDITIONS                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TIER 1: MINOR INFRACTIONS (0.1% - 1% stake slashed)                  │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  • Missed blocks (< 5% of assigned blocks)                            │  │
│  │  • Late vote extensions (> 2 second delay)                            │  │
│  │  • Stale attestations (> 1 hour old)                                  │  │
│  │                                                                        │  │
│  │  Penalty: Warning + 0.1% stake slash per incident                     │  │
│  │  Jail: No                                                             │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TIER 2: MODERATE INFRACTIONS (1% - 10% stake slashed)                │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  • Missed blocks (5% - 20% of assigned blocks)                        │  │
│  │  • Invalid compute job results (unintentional)                        │  │
│  │  • Attestation freshness violations (> 24 hours)                      │  │
│  │  • Hardware capability misrepresentation                              │  │
│  │                                                                        │  │
│  │  Penalty: 5% stake slash + 7 day jail                                 │  │
│  │  Jail: 7 days (no rewards, no job assignments)                        │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TIER 3: SEVERE INFRACTIONS (10% - 50% stake slashed)                 │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  • Double signing (equivocation)                                      │  │
│  │  • Intentionally wrong compute results                                │  │
│  │  • Jurisdiction violations (processing restricted data)               │  │
│  │  • Data exfiltration attempts                                         │  │
│  │                                                                        │  │
│  │  Penalty: 25% stake slash + 90 day jail                               │  │
│  │  Jail: 90 days                                                        │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TIER 4: CRITICAL INFRACTIONS (50% - 100% stake slashed + tombstone) │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │                                                                        │  │
│  │  • Collusion with other validators                                   │  │
│  │  • Long-range attacks                                                 │  │
│  │  • TEE bypass attempts                                                │  │
│  │  • Key extraction attacks                                             │  │
│  │  • Repeated severe infractions                                        │  │
│  │                                                                        │  │
│  │  Penalty: 100% stake slash + permanent ban (tombstoned)               │  │
│  │  Recovery: None - validator key permanently blacklisted               │  │
│  │                                                                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 7.2 Slashing Implementation

```rust
/// Slashing module
pub struct SlashingKeeper {
    /// Infraction registry
    infractions: InfractionRegistry,

    /// Validator jail status
    jail_status: JailRegistry,

    /// Tombstoned validators (permanent ban)
    tombstones: TombstoneRegistry,
}

impl SlashingKeeper {
    /// Process a detected infraction
    pub fn process_infraction(
        &mut self,
        ctx: &mut Context,
        validator: &ValidatorAddress,
        infraction: Infraction,
    ) -> Result<SlashingResult, SlashingError> {
        // Get validator's current stake
        let stake = self.get_validator_stake(ctx, validator)?;

        // Calculate slash amount based on infraction tier
        let slash_amount = match infraction.tier() {
            InfractionTier::Minor => stake * Decimal::percent(1),
            InfractionTier::Moderate => stake * Decimal::percent(5),
            InfractionTier::Severe => stake * Decimal::percent(25),
            InfractionTier::Critical => stake, // 100%
        };

        // Apply slash
        self.slash_stake(ctx, validator, slash_amount)?;

        // Apply jail if required
        let jail_duration = match infraction.tier() {
            InfractionTier::Minor => None,
            InfractionTier::Moderate => Some(Duration::days(7)),
            InfractionTier::Severe => Some(Duration::days(90)),
            InfractionTier::Critical => None, // Tombstoned instead
        };

        if let Some(duration) = jail_duration {
            self.jail_validator(ctx, validator, duration)?;
        }

        // Tombstone for critical infractions
        if infraction.tier() == InfractionTier::Critical {
            self.tombstone_validator(ctx, validator)?;
        }

        // Record infraction for history
        self.infractions.record(validator, &infraction)?;

        Ok(SlashingResult {
            validator: validator.clone(),
            slash_amount,
            jail_duration,
            tombstoned: infraction.tier() == InfractionTier::Critical,
        })
    }
}
```

---

## 8. Economic Security

### 8.1 Security Budget

The security of Proof of Useful Work depends on the economic cost to attack the network:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ECONOMIC SECURITY MODEL                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ATTACK COST CALCULATION                                                    │
│                                                                              │
│  To corrupt consensus, an attacker must control:                            │
│  • 1/3+ of stake (to halt network), OR                                      │
│  • 2/3+ of stake (to produce malicious blocks)                              │
│                                                                              │
│  Cost = (Required Stake) × (Token Price) + (Hardware Cost)                  │
│                                                                              │
│  Example (Mainnet Target):                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Total Stake: 100M AETHEL                                           │    │
│  │  Token Price: $10                                                   │    │
│  │  1/3 Attack: 33M AETHEL × $10 = $330M (halt)                        │    │
│  │  2/3 Attack: 67M AETHEL × $10 = $670M (corrupt)                     │    │
│  │                                                                      │    │
│  │  PLUS Hardware Costs:                                               │    │
│  │  67 validators × $500K (H100 + SGX setup) = $33.5M                  │    │
│  │                                                                      │    │
│  │  Total 2/3 Attack Cost: ~$700M                                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  SLASHING DETERRENCE                                                        │
│                                                                              │
│  Even if attack succeeds initially:                                         │
│  • 100% stake slashed for detected attackers                               │
│  • Hardware investment lost (attestation revoked)                          │
│  • Permanent ban (tombstone) prevents re-entry                             │
│                                                                              │
│  Net Attack Cost: > $700M (unrecoverable)                                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 Incentive Alignment

```rust
/// Validator reward distribution
pub struct RewardDistribution {
    /// Base block reward (inflation)
    pub block_reward: Amount,

    /// Compute job fees (from users)
    pub job_fees: Amount,

    /// MEV (if applicable)
    pub mev_reward: Amount,
}

impl RewardDistribution {
    /// Calculate validator reward for a block
    pub fn calculate(
        block: &Block,
        validator: &ValidatorAddress,
        config: &RewardConfig,
    ) -> Amount {
        // Base reward (inflation-funded)
        let base = config.block_reward;

        // Compute job rewards (proportional to jobs completed)
        let jobs_completed = block.count_jobs_by_validator(validator);
        let total_jobs = block.total_jobs();
        let job_share = if total_jobs > 0 {
            (jobs_completed as f64) / (total_jobs as f64)
        } else {
            0.0
        };

        // Fee revenue (after burn)
        let total_fees = block.total_fees();
        let burn_amount = Self::calculate_burn(total_fees, block.congestion());
        let distributable_fees = total_fees - burn_amount;

        // Validator's share of fees
        let fee_reward = distributable_fees * Decimal::from_f64(job_share);

        // Commission (validator keeps X%, rest to delegators)
        let commission_rate = config.get_commission(validator);
        let validator_reward = (base + fee_reward) * commission_rate;

        validator_reward
    }

    /// Calculate congestion-squared fee burn
    fn calculate_burn(total_fees: Amount, congestion: f64) -> Amount {
        // Burn = Fees × Congestion²
        // When congestion = 0.5 (50%), burn = 25% of fees
        // When congestion = 1.0 (100%), burn = 100% of fees
        let burn_rate = congestion * congestion;
        total_fees * Decimal::from_f64(burn_rate)
    }
}
```

---

## 9. Implementation Details

### 9.1 ABCI++ Handler Implementation

```go
// app/abci.go - Core ABCI++ handlers

// ExtendVote is called when a validator needs to create a vote extension
func (app *AethelredApp) ExtendVote(
    ctx context.Context,
    req *abci.RequestExtendVote,
) (*abci.ResponseExtendVote, error) {
    // Get completed jobs from this validator
    completedJobs := app.pocKeeper.GetCompletedJobs(ctx)

    // Generate fresh attestation
    attestation, err := app.teeService.GenerateAttestation()
    if err != nil {
        return nil, fmt.Errorf("failed to generate attestation: %w", err)
    }

    // Build vote extension
    ext := VoteExtension{
        ValidatorAddr:  app.validatorAddr,
        CompletedJobs:  completedJobs,
        Attestation:    attestation,
        Timestamp:      time.Now(),
    }

    // Sign the extension
    extBytes, err := ext.Marshal()
    if err != nil {
        return nil, fmt.Errorf("failed to marshal extension: %w", err)
    }

    signature, err := app.signer.Sign(extBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to sign extension: %w", err)
    }
    ext.Signature = signature

    return &abci.ResponseExtendVote{
        VoteExtension: ext.Marshal(),
    }, nil
}

// VerifyVoteExtension validates a vote extension from another validator
func (app *AethelredApp) VerifyVoteExtension(
    ctx context.Context,
    req *abci.RequestVerifyVoteExtension,
) (*abci.ResponseVerifyVoteExtension, error) {
    // Unmarshal the extension
    var ext VoteExtension
    if err := ext.Unmarshal(req.VoteExtension); err != nil {
        return &abci.ResponseVerifyVoteExtension{
            Status: abci.ResponseVerifyVoteExtension_REJECT,
        }, nil
    }

    // Verify signature
    if !app.verifySignature(ext) {
        return &abci.ResponseVerifyVoteExtension{
            Status: abci.ResponseVerifyVoteExtension_REJECT,
        }, nil
    }

    // Verify attestation
    if err := app.attestationVerifier.Verify(&ext.Attestation); err != nil {
        return &abci.ResponseVerifyVoteExtension{
            Status: abci.ResponseVerifyVoteExtension_REJECT,
        }, nil
    }

    // Verify each completed job
    for _, job := range ext.CompletedJobs {
        if err := app.verifyCompletedJob(&job); err != nil {
            return &abci.ResponseVerifyVoteExtension{
                Status: abci.ResponseVerifyVoteExtension_REJECT,
            }, nil
        }
    }

    return &abci.ResponseVerifyVoteExtension{
        Status: abci.ResponseVerifyVoteExtension_ACCEPT,
    }, nil
}

// PrepareProposal is called when this validator is the block proposer
func (app *AethelredApp) PrepareProposal(
    ctx context.Context,
    req *abci.RequestPrepareProposal,
) (*abci.ResponsePrepareProposal, error) {
    // Aggregate vote extensions from previous block
    var allCompletedJobs []CompletedJob
    for _, vote := range req.LocalLastCommit.Votes {
        if len(vote.VoteExtension) == 0 {
            continue
        }

        var ext VoteExtension
        if err := ext.Unmarshal(vote.VoteExtension); err != nil {
            continue
        }

        allCompletedJobs = append(allCompletedJobs, ext.CompletedJobs...)
    }

    // Create Digital Seals for completed jobs
    seals := app.createDigitalSeals(allCompletedJobs)

    // Calculate rewards
    rewards := app.calculateRewards(allCompletedJobs)

    // Calculate fee burns
    burns := app.calculateBurns(req.Txs)

    // Build the proposal
    proposal := &BlockProposal{
        Txs:           req.Txs,
        CompletedJobs: allCompletedJobs,
        Seals:         seals,
        Rewards:       rewards,
        Burns:         burns,
    }

    return &abci.ResponsePrepareProposal{
        Txs: proposal.EncodeTxs(),
    }, nil
}

// ProcessProposal validates a proposed block
func (app *AethelredApp) ProcessProposal(
    ctx context.Context,
    req *abci.RequestProcessProposal,
) (*abci.ResponseProcessProposal, error) {
    // Decode the proposal
    proposal, err := DecodeBlockProposal(req.Txs)
    if err != nil {
        return &abci.ResponseProcessProposal{
            Status: abci.ResponseProcessProposal_REJECT,
        }, nil
    }

    // Verify all completed jobs
    for _, job := range proposal.CompletedJobs {
        if err := app.verifyCompletedJob(&job); err != nil {
            return &abci.ResponseProcessProposal{
                Status: abci.ResponseProcessProposal_REJECT,
            }, nil
        }
    }

    // Verify reward calculations
    expectedRewards := app.calculateRewards(proposal.CompletedJobs)
    if !proposal.Rewards.Equal(expectedRewards) {
        return &abci.ResponseProcessProposal{
            Status: abci.ResponseProcessProposal_REJECT,
        }, nil
    }

    // Verify burn calculations
    expectedBurns := app.calculateBurns(req.Txs)
    if !proposal.Burns.Equal(expectedBurns) {
        return &abci.ResponseProcessProposal{
            Status: abci.ResponseProcessProposal_REJECT,
        }, nil
    }

    return &abci.ResponseProcessProposal{
        Status: abci.ResponseProcessProposal_ACCEPT,
    }, nil
}
```

### 9.2 Compute Job Keeper

```go
// x/poc/keeper/compute.go

// ComputeKeeper manages compute job lifecycle
type ComputeKeeper struct {
    storeKey     storetypes.StoreKey
    cdc          codec.Codec
    validatorSet ValidatorSet
    router       *UsefulWorkRouter
    teeService   TEEService
}

// SubmitJob handles a new compute job submission
func (k ComputeKeeper) SubmitJob(
    ctx sdk.Context,
    job *types.ComputeJob,
) (*types.JobSubmissionResult, error) {
    // Validate job parameters
    if err := job.Validate(); err != nil {
        return nil, fmt.Errorf("invalid job: %w", err)
    }

    // Check fee is sufficient
    minFee := k.calculateMinFee(ctx, job)
    if job.Fee.LT(minFee) {
        return nil, fmt.Errorf("fee too low: got %s, need %s", job.Fee, minFee)
    }

    // Route job to appropriate validator
    assignment, err := k.router.RouteJob(ctx, job)
    if err != nil {
        return nil, fmt.Errorf("failed to route job: %w", err)
    }

    // Lock collateral from validator
    if err := k.lockCollateral(ctx, assignment); err != nil {
        return nil, fmt.Errorf("failed to lock collateral: %w", err)
    }

    // Store job
    jobID := k.generateJobID(ctx)
    job.ID = jobID
    job.Status = types.JobStatusScheduled
    job.AssignedValidator = assignment.Validator
    job.ScheduledAt = ctx.BlockTime()

    k.SetJob(ctx, job)

    // Emit event
    ctx.EventManager().EmitEvent(
        sdk.NewEvent(
            types.EventTypeJobSubmitted,
            sdk.NewAttribute(types.AttributeKeyJobID, jobID.String()),
            sdk.NewAttribute(types.AttributeKeyValidator, assignment.Validator.String()),
        ),
    )

    return &types.JobSubmissionResult{
        JobID:      jobID,
        Validator:  assignment.Validator,
        Deadline:   assignment.Deadline,
        EstCost:    job.Fee,
    }, nil
}

// CompleteJob records a completed job result
func (k ComputeKeeper) CompleteJob(
    ctx sdk.Context,
    result *types.CompletedJob,
) error {
    // Get original job
    job, found := k.GetJob(ctx, result.JobID)
    if !found {
        return fmt.Errorf("job not found: %s", result.JobID)
    }

    // Verify validator is assigned to this job
    if !job.AssignedValidator.Equals(result.ValidatorAddr) {
        return fmt.Errorf("wrong validator")
    }

    // Verify execution proof
    if err := k.verifyExecutionProof(ctx, result); err != nil {
        return fmt.Errorf("invalid execution proof: %w", err)
    }

    // Update job status
    job.Status = types.JobStatusCompleted
    job.CompletedAt = ctx.BlockTime()
    job.Result = result

    k.SetJob(ctx, job)

    // Release collateral
    k.releaseCollateral(ctx, job)

    // Queue for Digital Seal creation
    k.queueForSeal(ctx, result)

    return nil
}
```

---

## 10. Performance Analysis

### 10.1 Throughput Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         THROUGHPUT ANALYSIS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FACTORS AFFECTING THROUGHPUT                                               │
│                                                                              │
│  1. Block Time: 3 seconds (CometBFT)                                        │
│  2. Block Size: 4 MB (configurable)                                         │
│  3. Transaction Size: ~500 bytes (average)                                  │
│  4. Compute Job Size: ~2 KB (average)                                       │
│                                                                              │
│  THEORETICAL MAXIMUM                                                        │
│                                                                              │
│  Standard Transactions:                                                     │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  TPS = (Block Size / Tx Size) / Block Time                          │    │
│  │      = (4,000,000 / 500) / 3                                        │    │
│  │      = 2,666 TPS (base transactions)                                │    │
│  │                                                                      │    │
│  │  With parallel execution: ~10,000 TPS                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  Compute Jobs:                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  Jobs per block = Validators × Avg Jobs per Validator               │    │
│  │                 = 100 × 20                                          │    │
│  │                 = 2,000 jobs per block                              │    │
│  │                                                                      │    │
│  │  Jobs per second = 2,000 / 3 = ~667 compute jobs/second             │    │
│  │                                                                      │    │
│  │  Note: Each job may involve complex AI inference                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  REAL-WORLD BENCHMARKS (Testnet)                                            │
│                                                                              │
│  ┌──────────────────────┬─────────────┬─────────────────────────────────┐   │
│  │ Metric               │ Achieved    │ Notes                           │   │
│  ├──────────────────────┼─────────────┼─────────────────────────────────┤   │
│  │ Block Time           │ 2.8s        │ Below 3s target                 │   │
│  │ Standard TPS         │ 12,500      │ With parallel execution         │   │
│  │ Compute Jobs/sec     │ 650         │ Llama-3 8B inference           │   │
│  │ Finality             │ 2.8s        │ Instant (no confirmations)      │   │
│  │ Attestation Verify   │ 10ms        │ Per job                         │   │
│  │ ZK Proof Verify      │ 50ms        │ Per proof (optional)            │   │
│  └──────────────────────┴─────────────┴─────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.2 Latency Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LATENCY BREAKDOWN                                  │
│                        (End-to-End Compute Job)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  STAGE                              │ LATENCY      │ CUMULATIVE       │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │  1. User submits job (RPC)          │   50ms       │     50ms         │  │
│  │  2. Mempool propagation             │  100ms       │    150ms         │  │
│  │  3. Router assignment               │   20ms       │    170ms         │  │
│  │  4. Validator receives job          │   50ms       │    220ms         │  │
│  │  5. TEE setup + attestation         │  100ms       │    320ms         │  │
│  │  6. Input decryption                │   10ms       │    330ms         │  │
│  │  7. Model loading (cached)          │   50ms       │    380ms         │  │
│  │  8. AI Inference (Llama-3 8B)       │  200ms       │    580ms         │  │
│  │  9. Output encryption               │   10ms       │    590ms         │  │
│  │  10. Proof generation               │   20ms       │    610ms         │  │
│  │  11. Vote extension                 │   10ms       │    620ms         │  │
│  │  12. Consensus (1 block)            │ 2800ms       │   3420ms         │  │
│  │  13. Seal creation                  │   10ms       │   3430ms         │  │
│  │  14. Response to user               │   50ms       │   3480ms         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  TOTAL END-TO-END LATENCY: ~3.5 seconds                                     │
│                                                                              │
│  Note: Inference latency varies by model size:                              │
│  • Small (< 1B params): 20-50ms                                             │
│  • Medium (1-10B params): 50-300ms                                          │
│  • Large (10B+ params): 300ms-2s                                            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 10.3 Scalability Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SCALABILITY ROADMAP                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHASE 1: VERTICAL (Current)                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • 100 validators with H100 GPUs                                    │    │
│  │  • Single global validator set                                      │    │
│  │  • Target: 1,000 compute jobs/second                                │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  PHASE 2: HORIZONTAL SHARDING (2027)                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Jurisdiction-specific shards:                                    │    │
│  │    - UAE Shard (data must stay in UAE)                              │    │
│  │    - EU Shard (GDPR-compliant)                                      │    │
│  │    - US Shard (HIPAA, SOX)                                          │    │
│  │    - Global Shard (no restrictions)                                 │    │
│  │  • Cross-shard communication via IBC                                │    │
│  │  • Target: 10,000 compute jobs/second                               │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  PHASE 3: ROLLUP ECOSYSTEM (2028)                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  • Application-specific rollups:                                    │    │
│  │    - Healthcare rollup (HIPAA-focused)                              │    │
│  │    - Finance rollup (PCI-DSS, SOX)                                  │    │
│  │    - Government rollup (classified data)                            │    │
│  │  • Aethelred L1 as settlement layer                                 │    │
│  │  • Target: 100,000+ compute jobs/second                             │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **PoUW** | Proof of Useful Work - Aethelred's consensus mechanism |
| **TEE** | Trusted Execution Environment - Hardware-isolated compute |
| **Vote Extension** | CometBFT ABCI++ feature for including extra data in votes |
| **Digital Seal** | On-chain proof of verified computation |
| **Attestation** | Cryptographic proof that code is running in genuine TEE |
| **MRENCLAVE** | Measurement of enclave code (Intel SGX) |
| **VRF** | Verifiable Random Function - Unpredictable, verifiable randomness |
| **Tombstone** | Permanent ban from validator set after critical offense |

---

## Next Steps

- **[Cryptographic Standards](cryptography.md)**: Hybrid signatures and attestation details
- **[Tokenomics](tokenomics.md)**: AETHEL utility and economic model
- **[Validator Guide](../guides/validator-setup.md)**: How to run a validator node

---

<p align="center">
  <em>© 2026 Aethelred Protocol Foundation. All Rights Reserved.</em>
</p>
