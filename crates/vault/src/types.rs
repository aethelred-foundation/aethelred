//! Core types for the Cruzible TEE service.

use serde::{Deserialize, Serialize};

/// Validator record submitted by the L1 chain for TEE scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInput {
    pub address: String,
    pub stake: u128,
    pub uptime_pct: f64,
    pub avg_response_ms: f64,
    pub geographic_region: String,
    pub country_code: String,
    pub operator_id: String,
    pub slash_count: u32,
    pub total_jobs_completed: u64,
    pub tee_public_key: String,
    pub commission_bps: u32,
}

/// Scored validator (output of TEE selection algorithm).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredValidator {
    pub address: String,
    pub stake: u128,
    pub performance_score: u32,
    pub decentralization_score: u32,
    pub reputation_score: u32,
    pub composite_score: u32,
    pub tee_public_key: String,
    pub commission_bps: u32,
    pub rank: u32,
}

/// Validator selection request.
///
/// The `eligible_universe_hash` and related fields are supplied by the L1
/// keeper (`BuildValidatorSelectionRequest`).  They describe the full set of
/// telemetry-eligible validators — including those *not* passed as candidates
/// — so the TEE can bind the universe commitment into its attestation payload.
///
/// Fields use `#[serde(default)]` for backward compatibility: older callers
/// that omit them will get empty/zero defaults, and the handler will reject
/// the request if the hash is missing (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectValidatorsRequest {
    pub validators: Vec<ValidatorInput>,
    pub target_count: usize,
    pub epoch: u64,
    pub config: SelectionConfig,

    /// Hex-encoded SHA-256 hash of the sorted eligible validator addresses
    /// (null-byte separated).  Computed by the L1 keeper's
    /// `computeEligibleUniverseHash()`.  Empty string ⇒ rejected by handler.
    #[serde(default)]
    pub eligible_universe_hash: String,

    /// Total number of active validators on-chain at request time.
    #[serde(default)]
    pub total_active_count: usize,

    /// Number of active validators that passed the telemetry freshness check.
    #[serde(default)]
    pub eligible_count: usize,

    /// Number of active validators excluded for stale/missing telemetry.
    #[serde(default)]
    pub skipped_stale_count: usize,
}

/// Weights and thresholds for validator scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionConfig {
    pub performance_weight: f64,
    pub decentralization_weight: f64,
    pub reputation_weight: f64,
    pub min_uptime_pct: f64,
    pub max_commission_bps: u32,
    pub max_per_region: usize,
    pub max_per_operator: usize,
    pub min_stake: u128,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            performance_weight: 0.4,
            decentralization_weight: 0.3,
            reputation_weight: 0.3,
            min_uptime_pct: 95.0,
            max_commission_bps: 1000,
            max_per_region: 0, // 0 = no limit (dynamic)
            max_per_operator: 3,
            min_stake: 32_000_000_000_000_000_000, // 32 AETHEL in wei
        }
    }
}

/// Validator selection result from TEE.
///
/// `eligible_universe_hash` echoes the universe commitment from the request
/// and is included in the attested payload (96 bytes:
/// `canonical_hash || policy_hash || universe_hash`), allowing on-chain
/// consumers to verify candidate-set completeness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectValidatorsResponse {
    pub selected: Vec<ScoredValidator>,
    pub epoch: u64,
    pub total_candidates: usize,
    pub selection_hash: String,
    pub attestation: AttestationDocument,

    /// Hex-encoded eligible-universe hash, echoed from the request and
    /// bound into the attestation payload.
    pub eligible_universe_hash: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Reward Calculation Types
// ─────────────────────────────────────────────────────────────────────────────

/// Individual reward allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardAllocation {
    pub address: String,
    pub base_reward: u128,
    pub performance_bonus: u128,
    pub mev_share: u128,
    pub total_reward: u128,
}

/// Reward calculation request.
///
/// Note: `protocol_fee_bps` is intentionally absent. The protocol fee is
/// derived inside the TEE from the enclave-internal constant
/// `PROTOCOL_FEE_BPS` (matching Cruzible.sol) so that a caller cannot
/// request a lower fee while still obtaining a valid attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculateRewardsRequest {
    pub epoch: u64,
    pub total_rewards: u128,
    pub mev_revenue: u128,
    pub validators: Vec<ScoredValidator>,
    pub staker_stakes: Vec<StakerStake>,

    /// Hex-encoded SHA-256 hash of the canonical stake snapshot (sorted
    /// staker addresses, shares, and delegations).  Computed by the L1 keeper.
    /// The TEE independently recomputes this from `staker_stakes` and rejects
    /// the request if the hashes differ — preventing a relayer from omitting
    /// stakers or skewing balances while still obtaining a valid attestation.
    /// Empty string ⇒ rejected by handler (fail-closed).
    #[serde(default)]
    pub stake_snapshot_hash: String,

    /// Hex-encoded SHA-256 canonical validator set hash.  Computed by the L1
    /// keeper's `computeValidatorSetHash()` from the current epoch's validator
    /// set (the same hash that `updateValidatorSet()` verified via TEE
    /// attestation).  The TEE independently recomputes this from `validators`
    /// and rejects the request if the hashes differ — preventing a relayer
    /// from supplying manipulated validator scores for performance-weighted
    /// reward distribution.
    /// Empty string ⇒ rejected by handler (fail-closed).
    #[serde(default)]
    pub validator_set_hash: String,
}

/// A staker's stake record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakerStake {
    pub address: String,
    pub shares: u128,
    pub delegated_to: String,
}

/// Reward calculation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalculateRewardsResponse {
    pub epoch: u64,
    pub allocations: Vec<RewardAllocation>,
    pub total_distributed: u128,
    pub protocol_fee: u128,
    pub merkle_root: String,
    pub merkle_proofs: Vec<MerkleProofEntry>,
    pub attestation: AttestationDocument,

    /// Hex-encoded stake snapshot hash, bound into the attestation payload.
    pub stake_snapshot_hash: String,

    /// Hex-encoded validator set hash, bound into the attestation payload.
    pub validator_set_hash: String,
}

/// Merkle proof for an individual reward claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofEntry {
    pub address: String,
    pub amount: u128,
    pub proof: Vec<String>,
    pub leaf: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Delegation Attestation Types
// ─────────────────────────────────────────────────────────────────────────────

/// Request for the `/attest-delegation` endpoint.
///
/// The TEE independently recomputes the delegation registry root from the
/// supplied staker set and produces a 96-byte attestation that
/// `Cruzible.commitDelegationSnapshot()` verifies on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestDelegationRequest {
    pub epoch: u64,
    pub staker_stakes: Vec<StakerStake>,

    /// Hex-encoded staker registry root that the keeper computed.
    /// The TEE independently recomputes and verifies this from `staker_stakes`.
    #[serde(default)]
    pub staker_registry_root: String,
}

/// Response from the `/attest-delegation` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestDelegationResponse {
    pub epoch: u64,

    /// Hex-encoded delegation registry root independently computed by the TEE.
    pub delegation_root: String,

    /// Hex-encoded staker registry root independently computed by the TEE.
    pub staker_registry_root: String,

    /// TEE attestation over the 96-byte payload:
    /// `abi.encode(epoch, delegationRoot, stakerRegistryRoot)`.
    pub attestation: AttestationDocument,
}

// ─────────────────────────────────────────────────────────────────────────────
// MEV Protection Types
// ─────────────────────────────────────────────────────────────────────────────

/// Commit-reveal commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    pub validator: String,
    pub commitment_hash: String,
    pub timestamp: u64,
}

/// Commit-reveal reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    pub validator: String,
    pub block_data: String,
    pub nonce: String,
    pub timestamp: u64,
}

/// MEV ordering request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTransactionsRequest {
    pub epoch: u64,
    pub commitments: Vec<Commitment>,
    pub reveals: Vec<Reveal>,
}

/// MEV ordering result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderTransactionsResponse {
    pub epoch: u64,
    pub ordered_blocks: Vec<ValidatedReveal>,
    pub invalid_reveals: Vec<String>,
    pub attestation: AttestationDocument,
}

/// A validated and ordered reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedReveal {
    pub validator: String,
    pub block_data: String,
    pub ordering_timestamp: u64,
    pub position: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// TEE Attestation Types
// ─────────────────────────────────────────────────────────────────────────────

/// TEE attestation document (platform-agnostic).
///
/// This format matches the on-chain verifiers:
///   - Go native: `x/vault/types.TEEAttestation`
///   - Solidity:  `VaultTEEVerifier.DecodedAttestation`
///
/// `platform` is a uint8 (0=SGX, 1=Nitro, 2=SEV, 255=Mock).
/// `signature` is a hex-encoded 65-byte secp256k1 ECDSA signature (R[32]‖S[32]‖V[1]).
///
/// `platform_evidence` is hex-encoded ABI-encoded platform-specific evidence
/// that binds this attestation to real TEE hardware. The evidence format varies
/// by platform:
///   - SGX: (bytes32 mrenclave, bytes32 mrsigner, bytes32 reportData, uint16 isvProdId, uint16 isvSvn)
///   - Nitro: (bytes32 pcrHash0, bytes32 pcrHash1, bytes32 pcrHash2, bytes32 userData)
///   - SEV: (bytes32 measurementHash, bytes32 hostData, bytes32 reportData, uint8 vmpl)
/// The `reportData`/`userData` field contains the attestation digest, proving
/// the evidence was generated for this specific attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub platform: u8,
    pub timestamp: u64,
    pub nonce: String,
    pub enclave_hash: String,
    pub signer_hash: String,
    pub payload_hash: String,
    pub platform_evidence: String,
    pub signature: String,
}

/// Per-type attestation counts for observability.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationCountByType {
    pub validator_selection: u64,
    pub reward_calculation: u64,
    pub mev_ordering: u64,
    pub delegation_attestation: u64,
}

/// Health check response.
///
/// Extended for production readiness with authentication status, rate limit
/// configuration, and per-type attestation breakdowns. The `/health` endpoint
/// is always unauthenticated (load-balancer probes, k8s liveness) so no
/// secrets are exposed — only operational metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub service: String,
    pub status: String,
    pub version: String,
    pub platform: String,
    pub epoch: u64,
    pub uptime_seconds: u64,
    pub total_attestations: u64,
    /// Whether bearer-token authentication is enabled.
    pub auth_enabled: bool,
    /// Configured rate limit (requests per second). 0 = unlimited.
    pub rate_limit_rps: u32,
    /// ISO-8601 timestamp of the last successful attestation, or null if none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attestation_at: Option<String>,
    /// Per-type attestation breakdown.
    pub attestation_counts: AttestationCountByType,
    /// Total request errors (4xx + 5xx) since startup.
    pub total_errors: u64,
    /// Total authentication failures (401) since startup.
    pub auth_failures: u64,
}

/// Capabilities response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesResponse {
    pub platform: String,
    pub supported_operations: Vec<String>,
    pub max_validators: usize,
    pub max_stakers: usize,
    pub max_commitments: usize,
    pub attestation_types: Vec<String>,
}

/// Prometheus-compatible metrics response (text exposition format).
///
/// Returned by the `/metrics` endpoint for scraping by Prometheus, Datadog,
/// or any OpenMetrics-compatible collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub total_attestations: u64,
    pub attestation_counts: AttestationCountByType,
    pub total_errors: u64,
    pub auth_failures: u64,
    pub current_epoch: u64,
    pub rate_limit_rps: u32,
}
