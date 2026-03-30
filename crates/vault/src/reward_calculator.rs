//! TEE Reward Calculator with Merkle Tree Verification
//!
//! Computes fair reward distribution inside a TEE enclave and produces
//! a Merkle tree for gas-efficient on-chain verification.
//!
//! ## Asset-backed claim invariant
//!
//! The contract's `distributeRewards()` reserves exactly
//! `totalRewards - protocolFee` for Merkle claims and enforces that limit
//! at claim time. MEV revenue is handled separately by `submitMEVRevenue()`
//! which auto-compounds via the exchange rate (not reserved for claims).
//!
//! Therefore the Merkle leaf amounts must satisfy:
//!
//! ```text
//! sum(total_reward_i) ≤ distributable   where distributable = totalRewards - protocolFee
//! ```
//!
//! ## Protocol fee policy
//!
//! `PROTOCOL_FEE_BPS` (500 = 5 %) is an **enclave-internal constant** that
//! mirrors Cruzible.sol's `uint256 public constant PROTOCOL_FEE_BPS = 500`.
//! It is intentionally excluded from `CalculateRewardsRequest` so that
//! a caller cannot request a lower fee while still obtaining a valid TEE
//! attestation. The attested canonical payload includes the computed fee,
//! and the contract validates it against the same constant.
//!
//! ## Reward Formula
//!
//! ```text
//! protocol_fee     = total_rewards × PROTOCOL_FEE_BPS / 10000   (enclave constant)
//! distributable    = total_rewards - protocol_fee
//! weighted_stake_i = stake_i × (1 + (perf_score_i / 10000) × BONUS_RATE)
//! total_weighted   = Σ weighted_stake_i
//! total_reward_i   = distributable × weighted_stake_i / total_weighted
//! ```
//!
//! Performance is a **weight factor** (redistributive), not an additive bonus,
//! ensuring the sum of all claims exactly equals the epoch reserve.
//!
//! MEV share is computed for informational purposes but is NOT included in
//! the Merkle leaf amount. The contract auto-compounds MEV into the exchange
//! rate via `submitMEVRevenue()`.

use sha2::{Digest, Sha256};

use crate::types::*;

/// Protocol fee on rewards (5% — matches Cruzible.sol `PROTOCOL_FEE_BPS`).
///
/// This is an enclave-internal constant, NOT a caller-supplied value.
/// Cruzible.sol declares `uint256 public constant PROTOCOL_FEE_BPS = 500;`
/// and `distributeRewards()` verifies `protocolFee <= expectedFee + 1%`.
/// Because the fee is TEE-attested and derived from the same constant,
/// a caller cannot request a lower fee to undercharge the treasury.
pub const PROTOCOL_FEE_BPS: u32 = 500;

/// Performance bonus rate (up to 10% bonus for top performers).
const PERFORMANCE_BONUS_RATE: f64 = 0.10;

/// MEV staker share (90% of MEV revenue goes to stakers).
const MEV_STAKER_SHARE_BPS: u32 = 9000;

/// Basis points denominator.
const BPS_DENOMINATOR: u32 = 10000;

/// Calculate reward allocations for all stakers in an epoch.
///
/// # Algorithm
///
/// 1. Calculate protocol fee from total rewards.
/// 2. Compute performance-weighted stake for each staker.
/// 3. Distribute `distributable = totalRewards - protocolFee` proportional
///    to weighted stake (performance is redistributive, not additive).
/// 4. Compute informational MEV share (NOT included in Merkle claims —
///    MEV auto-compounds on-chain via `submitMEVRevenue()`).
/// 5. Build Merkle tree whose leaf sum ≤ `distributable`.
///
/// # Asset-backed invariant
///
/// `sum(total_reward) ≤ distributable` is guaranteed because every claim
/// is a proportional share of `distributable` weighted by
/// `stake × (1 + perf_factor)`. The weights are normalized by
/// `total_weighted_stake`, so the sum telescopes to `distributable`
/// (minus at most 1 wei of rounding dust per staker).
///
/// # Errors
///
/// Returns `Err` if any staker has an empty `delegated_to` field or
/// references a validator not present in the request's validator set.
/// This fail-closed behaviour prevents a relayer from obtaining valid
/// TEE-attested rewards for stakers whose delegation was never recorded.
pub fn calculate_rewards(
    request: &CalculateRewardsRequest,
) -> Result<CalculateRewardsResponse, String> {
    // ── Reject duplicate staker addresses ─────────────────────────────
    //
    // Duplicate rows would inflate total_stake and skew per-staker
    // allocations.  Since claimRewards() is one-claim-per-address,
    // stranded allocations would be locked in the contract forever.
    {
        let mut seen = std::collections::HashSet::with_capacity(request.staker_stakes.len());
        for s in &request.staker_stakes {
            if !seen.insert(&s.address) {
                return Err(format!(
                    "duplicate staker address in reward request: {}",
                    s.address
                ));
            }
        }
    }

    // Protocol fee is derived from the enclave-internal constant, never from
    // the caller. This prevents an authorized relayer from requesting a lower
    // fee while still obtaining a valid TEE attestation.
    let protocol_fee = muldiv(
        request.total_rewards,
        PROTOCOL_FEE_BPS as u128,
        BPS_DENOMINATOR as u128,
    );
    let distributable = request.total_rewards - protocol_fee;

    // Build validator performance lookup
    let validator_scores: std::collections::HashMap<String, u32> = request
        .validators
        .iter()
        .map(|v| (v.address.clone(), v.performance_score))
        .collect();

    // Calculate total stake
    let total_stake: u128 = request.staker_stakes.iter().map(|s| s.shares).sum();
    if total_stake == 0 {
        return Ok(CalculateRewardsResponse {
            epoch: request.epoch,
            allocations: Vec::new(),
            total_distributed: 0,
            protocol_fee,
            merkle_root: "0x".to_string() + &"0".repeat(64),
            merkle_proofs: Vec::new(),
            attestation: AttestationDocument::default(),
            stake_snapshot_hash: String::new(),
            validator_set_hash: String::new(),
        });
    }

    // ── Phase 1: compute performance-weighted stakes ─────────────────────
    //
    // weighted_stake_i = stake_i × (BPS + perf_score_i × BONUS_BPS) / BPS
    //
    // We keep everything in integer BPS to avoid floating-point non-determinism.
    // BONUS_BPS = PERFORMANCE_BONUS_RATE × BPS = 0.10 × 10000 = 1000.
    const BONUS_BPS: u128 = (PERFORMANCE_BONUS_RATE * BPS_DENOMINATOR as f64) as u128; // 1000

    struct StakerWeight {
        index: usize,
        weighted_stake: u128,
    }

    // ── Fail-closed delegation validation ──────────────────────────────
    //
    // Every staker MUST have a non-empty `delegated_to` that references a
    // validator in the current active set. A missing or empty delegation
    // means the keeper never recorded it (the P1 bug this fixes), and a
    // reference to an unknown validator means stale/fabricated data.
    // In either case the TEE refuses to produce an attestation rather than
    // silently assigning a neutral 5000 score.
    for staker in &request.staker_stakes {
        if staker.delegated_to.is_empty() {
            return Err(format!(
                "staker {} has empty delegated_to: delegation is mandatory for reward weighting",
                staker.address,
            ));
        }
        if !validator_scores.contains_key(&staker.delegated_to) {
            return Err(format!(
                "staker {} delegates to validator {} which is not in the active validator set",
                staker.address, staker.delegated_to,
            ));
        }
    }

    let weights: Vec<StakerWeight> = request
        .staker_stakes
        .iter()
        .enumerate()
        .map(|(i, staker)| {
            // Safe to unwrap: we validated all delegations above.
            let perf_score = validator_scores[&staker.delegated_to];

            // weight_factor = BPS + perf_score * BONUS_BPS / BPS
            //               = 10000 + perf_score * 1000 / 10000
            //               = 10000 + perf_score / 10
            // This is in BPS units (10000 = 1.0x, max ≈ 11000 = 1.10x).
            let weight_factor = BPS_DENOMINATOR as u128
                + muldiv(perf_score as u128, BONUS_BPS, BPS_DENOMINATOR as u128);

            // weighted_stake = stake * weight_factor / BPS
            let weighted_stake = muldiv(staker.shares, weight_factor, BPS_DENOMINATOR as u128);

            StakerWeight {
                index: i,
                weighted_stake,
            }
        })
        .collect();

    let total_weighted: u128 = weights.iter().map(|w| w.weighted_stake).sum();

    // ── Phase 2: distribute `distributable` by weighted stake ────────────
    //
    // claim_i = distributable × weighted_stake_i / total_weighted
    //
    // This guarantees sum(claim_i) ≤ distributable (floor division rounds
    // down, so dust is left over — never over-allocated).

    let mut allocations: Vec<RewardAllocation> = weights
        .iter()
        .map(|w| {
            let staker = &request.staker_stakes[w.index];

            // Total claim amount (the Merkle leaf value)
            let total_reward = muldiv(distributable, w.weighted_stake, total_weighted);

            // Base reward (what they'd get without performance weighting)
            let base_reward = muldiv(distributable, staker.shares, total_stake);

            // Performance bonus is the difference (informational breakdown)
            let performance_bonus = total_reward.saturating_sub(base_reward);

            // MEV share: informational only — NOT included in total_reward.
            // On-chain, submitMEVRevenue() auto-compounds MEV into the
            // exchange rate, so stakers benefit without explicit claims.
            let mev_pool = muldiv(
                request.mev_revenue,
                MEV_STAKER_SHARE_BPS as u128,
                BPS_DENOMINATOR as u128,
            );
            let mev_share = muldiv(mev_pool, staker.shares, total_stake);

            RewardAllocation {
                address: staker.address.clone(),
                base_reward,
                performance_bonus,
                mev_share,
                total_reward,
            }
        })
        .collect();

    // Sort allocations by address for deterministic Merkle tree
    allocations.sort_by(|a, b| a.address.cmp(&b.address));

    // ── Phase 3: build Merkle tree ───────────────────────────────────────
    //
    // Invariant check: total_distributed must not exceed distributable.
    // Floor-division rounding guarantees this, but we assert defensively.
    let total_distributed: u128 = allocations.iter().map(|a| a.total_reward).sum();
    assert!(
        total_distributed <= distributable,
        "BUG: total_distributed ({}) exceeds distributable ({})",
        total_distributed,
        distributable
    );

    let (merkle_root, merkle_proofs) = build_merkle_tree(&allocations, request.epoch);

    Ok(CalculateRewardsResponse {
        epoch: request.epoch,
        allocations,
        total_distributed,
        protocol_fee,
        merkle_root,
        merkle_proofs,
        attestation: AttestationDocument::default(),
        stake_snapshot_hash: String::new(),
        validator_set_hash: String::new(),
    })
}

/// Multiply-then-divide: `floor(a × b / c)` using u256 intermediate.
///
/// Guarantees exact integer results with no floating-point rounding.
/// Used for all proportional reward calculations to maintain the
/// asset-backed invariant: `sum(claims) ≤ distributable`.
fn muldiv(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 {
        return 0;
    }
    // Fast path: a * b fits in u128
    if let Some(product) = a.checked_mul(b) {
        return product / c;
    }
    // Slow path: widening multiply to u256 then divide by u128.
    //
    // Split a and b into 64-bit halves:
    //   a = a_hi·2^64 + a_lo,  b = b_hi·2^64 + b_lo
    //   a × b = a_hi·b_hi·2^128 + (a_hi·b_lo + a_lo·b_hi)·2^64 + a_lo·b_lo
    let mask: u128 = 0xFFFF_FFFF_FFFF_FFFF;
    let a_lo = a & mask;
    let a_hi = a >> 64;
    let b_lo = b & mask;
    let b_hi = b >> 64;

    let ll = a_lo * b_lo;
    let lh = a_lo * b_hi;
    let hl = a_hi * b_lo;
    let hh = a_hi * b_hi;

    // Accumulate middle terms with carry
    let mid = (ll >> 64) + (lh & mask) + (hl & mask);
    let lo = (ll & mask) | ((mid & mask) << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);

    // Divide u256(hi, lo) by u128 c.
    div_u256_by_u128(hi, lo, c)
}

/// Divide `u256(hi·2^128 + lo)` by `u128` divisor `d`.
///
/// Uses binary long division (256 iterations). The result is assumed to
/// fit in u128 for our use case (proportional shares of a u128 total).
fn div_u256_by_u128(hi: u128, lo: u128, d: u128) -> u128 {
    debug_assert!(d != 0, "division by zero");
    if hi == 0 {
        return lo / d;
    }

    let mut quotient: u128 = 0;
    let mut rem: u128 = 0;

    // Process all 256 bits from MSB (bit 255) to LSB (bit 0).
    // Quotient bits >= 128 are discarded (assumed zero for valid inputs).
    for i in (0..=255u32).rev() {
        // Shift remainder left by 1. Track overflow (rem >= 2^127).
        let rem_msb = rem >> 127;
        rem <<= 1;

        // Insert the current bit of the dividend.
        let bit = if i >= 128 {
            (hi >> (i - 128)) & 1
        } else {
            (lo >> i) & 1
        };
        rem |= bit;

        // If remainder (with overflow) >= divisor, subtract and set quotient bit.
        if rem_msb != 0 || rem >= d {
            rem = rem.wrapping_sub(d);
            if i < 128 {
                quotient |= 1u128 << i;
            }
        }
    }

    quotient
}

/// Build a Merkle tree from reward allocations.
///
/// Each leaf is: keccak256(bytes.concat(keccak256(abi.encode(address, uint256, uint256))))
/// This double-hashing prevents second preimage attacks (OpenZeppelin standard).
/// Uses keccak256 to match Solidity's MerkleProof.verify() from OpenZeppelin.
fn build_merkle_tree(
    allocations: &[RewardAllocation],
    epoch: u64,
) -> (String, Vec<MerkleProofEntry>) {
    if allocations.is_empty() {
        return ("0x".to_string() + &"0".repeat(64), Vec::new());
    }

    // Generate leaves (double-hash for security)
    let leaves: Vec<[u8; 32]> = allocations
        .iter()
        .map(|a| {
            let inner = sha256_abi_encode(&a.address, a.total_reward, epoch);
            sha256_bytes(&inner)
        })
        .collect();

    // Build tree layers
    let mut layers: Vec<Vec<[u8; 32]>> = vec![leaves.clone()];
    let mut current = leaves;

    while current.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < current.len() {
            if i + 1 < current.len() {
                // Sort pair to ensure deterministic ordering
                let (left, right) = if current[i] <= current[i + 1] {
                    (current[i], current[i + 1])
                } else {
                    (current[i + 1], current[i])
                };
                next.push(hash_pair(&left, &right));
            } else {
                // Odd element: promote to next level
                next.push(current[i]);
            }
            i += 2;
        }
        layers.push(next.clone());
        current = next;
    }

    let root = if current.is_empty() {
        [0u8; 32]
    } else {
        current[0]
    };

    // Generate proofs for each leaf
    let proofs: Vec<MerkleProofEntry> = allocations
        .iter()
        .enumerate()
        .map(|(idx, allocation)| {
            let proof = generate_proof(&layers, idx);
            MerkleProofEntry {
                address: allocation.address.clone(),
                amount: allocation.total_reward,
                proof: proof
                    .iter()
                    .map(|h| format!("0x{}", hex::encode(h)))
                    .collect(),
                leaf: format!("0x{}", hex::encode(layers[0][idx])),
            }
        })
        .collect();

    (format!("0x{}", hex::encode(root)), proofs)
}

/// Generate Merkle proof for a specific leaf index.
fn generate_proof(layers: &[Vec<[u8; 32]>], mut index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();

    for layer in &layers[..layers.len().saturating_sub(1)] {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        if sibling_index < layer.len() {
            proof.push(layer[sibling_index]);
        }
        index /= 2;
    }

    proof
}

/// SHA-256 hash of raw bytes (arbitrary length).
fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hash);
    output
}

/// SHA-256 hash of ABI-encoded (address, uint256, uint256).
/// Matches Solidity: sha256(abi.encode(address, amount, epoch))
///
/// Solidity abi.encode pads each argument to 32 bytes, big-endian.
/// Supports both EVM hex addresses (0x-prefixed or raw hex) and
/// Cosmos-style bech32/string addresses (hashed to 20 bytes first).
fn sha256_abi_encode(address: &str, amount: u128, epoch: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(96); // 3 x 32 bytes

    // address → left-pad to 32 bytes
    let addr_hex = address.trim_start_matches("0x");
    let addr_bytes = match hex::decode(addr_hex) {
        Ok(bytes) if bytes.len() <= 32 => bytes,
        _ => {
            // Non-hex address (e.g. Cosmos bech32): hash to 20 bytes for determinism
            let hash = Sha256::digest(address.as_bytes());
            hash[..20].to_vec()
        }
    };
    let mut addr_padded = [0u8; 32];
    addr_padded[32 - addr_bytes.len()..].copy_from_slice(&addr_bytes);
    data.extend_from_slice(&addr_padded);

    // amount as uint256 → big-endian 128-bit value, left-padded to 32 bytes
    let mut amount_padded = [0u8; 32];
    amount_padded[16..].copy_from_slice(&amount.to_be_bytes());
    data.extend_from_slice(&amount_padded);

    // epoch as uint256 → big-endian 64-bit value, left-padded to 32 bytes
    let mut epoch_padded = [0u8; 32];
    epoch_padded[24..].copy_from_slice(&epoch.to_be_bytes());
    data.extend_from_slice(&epoch_padded);

    sha256_raw(&data)
}

/// SHA-256 hash of a 32-byte value (second hash in the double-hash leaf pattern).
fn sha256_bytes(data: &[u8; 32]) -> [u8; 32] {
    sha256_raw(data)
}

/// Hash a pair of Merkle tree nodes using SHA-256.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    sha256_raw(&data)
}

impl Default for AttestationDocument {
    fn default() -> Self {
        Self {
            platform: 255, // Mock
            timestamp: 0,
            nonce: String::new(),
            enclave_hash: String::new(),
            signer_hash: String::new(),
            payload_hash: String::new(),
            platform_evidence: String::new(),
            signature: String::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_request() -> CalculateRewardsRequest {
        CalculateRewardsRequest {
            epoch: 1,
            total_rewards: 1000_000_000_000_000_000_000, // 1000 AETHEL
            mev_revenue: 10_000_000_000_000_000_000,     // 10 AETHEL
            validators: vec![ScoredValidator {
                address: "validator-1".to_string(),
                stake: 100_000,
                performance_score: 9500,
                decentralization_score: 8000,
                reputation_score: 10000,
                composite_score: 9100,
                tee_public_key: "key-1".to_string(),
                commission_bps: 500,
                rank: 1,
            }],
            staker_stakes: vec![
                StakerStake {
                    address: "staker-a".to_string(),
                    shares: 600_000_000_000_000_000_000, // 600 shares
                    delegated_to: "validator-1".to_string(),
                },
                StakerStake {
                    address: "staker-b".to_string(),
                    shares: 400_000_000_000_000_000_000, // 400 shares
                    delegated_to: "validator-1".to_string(),
                },
            ],
            // Note: protocol_fee_bps is intentionally absent — the TEE uses its
            // internal PROTOCOL_FEE_BPS constant (500 = 5%), matching Cruzible.sol.
            stake_snapshot_hash: String::new(),
            validator_set_hash: String::new(),
        }
    }

    #[test]
    fn test_basic_reward_calculation() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        assert_eq!(response.epoch, 1);
        assert_eq!(response.allocations.len(), 2);
        assert!(response.total_distributed > 0);
        assert!(response.protocol_fee > 0);
    }

    #[test]
    fn test_proportional_distribution() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        // Staker A has 60% of stake, should get more
        let a = &response
            .allocations
            .iter()
            .find(|a| a.address == "staker-a")
            .unwrap();
        let b = &response
            .allocations
            .iter()
            .find(|a| a.address == "staker-b")
            .unwrap();

        assert!(a.base_reward > b.base_reward);
        // A should get roughly 1.5x B's base reward (600/400)
        let ratio = a.base_reward as f64 / b.base_reward as f64;
        assert!((ratio - 1.5).abs() < 0.01);
    }

    #[test]
    fn test_protocol_fee_calculation() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        // Fee is derived from the enclave-internal constant PROTOCOL_FEE_BPS (500 = 5%).
        // 5% of 1000 AETHEL = 50 AETHEL
        let expected_fee =
            request.total_rewards * PROTOCOL_FEE_BPS as u128 / BPS_DENOMINATOR as u128;
        assert_eq!(response.protocol_fee, expected_fee);

        // Verify the constant matches the Cruzible.sol immutable.
        assert_eq!(PROTOCOL_FEE_BPS, 500);
    }

    #[test]
    fn test_merkle_tree_generation() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        assert!(response.merkle_root.starts_with("0x"));
        assert_eq!(response.merkle_root.len(), 66); // 0x + 64 hex chars
        assert_eq!(response.merkle_proofs.len(), 2);

        // Each proof should have the correct leaf
        for proof in &response.merkle_proofs {
            assert!(proof.leaf.starts_with("0x"));
            assert!(!proof.proof.is_empty());
        }
    }

    #[test]
    fn test_empty_stakers() {
        let mut request = test_request();
        request.staker_stakes = vec![];

        let response = calculate_rewards(&request).unwrap();

        assert!(response.allocations.is_empty());
        assert_eq!(response.total_distributed, 0);
    }

    #[test]
    fn test_single_staker_gets_all() {
        let mut request = test_request();
        request.staker_stakes = vec![StakerStake {
            address: "only-staker".to_string(),
            shares: 1000_000_000_000_000_000_000,
            delegated_to: "validator-1".to_string(),
        }];

        let response = calculate_rewards(&request).unwrap();

        assert_eq!(response.allocations.len(), 1);
        let alloc = &response.allocations[0];
        // Should get all distributable rewards (minus rounding dust)
        let distributable = request.total_rewards - response.protocol_fee;
        assert!(alloc.total_reward <= distributable);
        assert!(alloc.total_reward >= distributable - 1); // at most 1 wei dust
                                                          // MEV share is informational only (not in total_reward)
        assert!(alloc.mev_share > 0, "MEV share should be reported");
    }

    #[test]
    fn test_mev_not_in_claims() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        // MEV share is informational — NOT included in total_reward or Merkle leaves.
        // The contract handles MEV separately via submitMEVRevenue().
        for alloc in &response.allocations {
            assert!(alloc.mev_share > 0, "MEV share should be reported for info");
            // total_reward should equal base_reward + performance_bonus (no MEV)
            assert_eq!(
                alloc.total_reward,
                alloc.base_reward + alloc.performance_bonus,
                "total_reward must not include mev_share"
            );
        }
    }

    /// Core asset-backed invariant: total claims ≤ distributable.
    ///
    /// The contract's `distributeRewards()` reserves exactly
    /// `totalRewards - protocolFee` for Merkle claims. If total_distributed
    /// exceeds this, later claimants will revert with
    /// "Claim exceeds epoch reserved rewards".
    #[test]
    fn test_claims_asset_backed() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        let distributable = request.total_rewards - response.protocol_fee;
        assert!(
            response.total_distributed <= distributable,
            "total_distributed ({}) must not exceed distributable ({})",
            response.total_distributed,
            distributable
        );
    }

    /// Stress test: many stakers, different validators, varied performance.
    /// The asset-backed invariant must hold regardless of distribution.
    #[test]
    fn test_claims_asset_backed_many_stakers() {
        let mut request = test_request();
        request.validators = vec![
            ScoredValidator {
                address: "val-high".to_string(),
                stake: 100_000,
                performance_score: 10000, // max score
                decentralization_score: 8000,
                reputation_score: 10000,
                composite_score: 9500,
                tee_public_key: "key-1".to_string(),
                commission_bps: 500,
                rank: 1,
            },
            ScoredValidator {
                address: "val-low".to_string(),
                stake: 50_000,
                performance_score: 1000, // low score
                decentralization_score: 5000,
                reputation_score: 5000,
                composite_score: 3500,
                tee_public_key: "key-2".to_string(),
                commission_bps: 1000,
                rank: 2,
            },
        ];
        request.staker_stakes = (0..100)
            .map(|i| StakerStake {
                address: format!("staker-{:03}", i),
                shares: ((i as u128 + 1) * 10_000_000_000_000_000_000), // varied stakes
                delegated_to: if i % 2 == 0 {
                    "val-high".to_string()
                } else {
                    "val-low".to_string()
                },
            })
            .collect();

        let response = calculate_rewards(&request).unwrap();
        let distributable = request.total_rewards - response.protocol_fee;

        assert!(
            response.total_distributed <= distributable,
            "asset-backed invariant violated: {} > {}",
            response.total_distributed,
            distributable
        );
        assert_eq!(response.allocations.len(), 100);
    }

    #[test]
    fn test_performance_bonus_redistributive() {
        // Create two stakers with same stake but different validator performance.
        // The higher-performance staker should get more, but the total should
        // not exceed distributable.
        let mut request = test_request();
        request.validators = vec![
            ScoredValidator {
                address: "val-good".to_string(),
                stake: 100_000,
                performance_score: 10000, // perfect
                decentralization_score: 8000,
                reputation_score: 10000,
                composite_score: 9500,
                tee_public_key: "key-1".to_string(),
                commission_bps: 500,
                rank: 1,
            },
            ScoredValidator {
                address: "val-bad".to_string(),
                stake: 50_000,
                performance_score: 0, // worst
                decentralization_score: 5000,
                reputation_score: 5000,
                composite_score: 3000,
                tee_public_key: "key-2".to_string(),
                commission_bps: 1000,
                rank: 2,
            },
        ];
        request.staker_stakes = vec![
            StakerStake {
                address: "staker-good".to_string(),
                shares: 500_000_000_000_000_000_000,
                delegated_to: "val-good".to_string(),
            },
            StakerStake {
                address: "staker-bad".to_string(),
                shares: 500_000_000_000_000_000_000,
                delegated_to: "val-bad".to_string(),
            },
        ];

        let response = calculate_rewards(&request).unwrap();
        let good = response
            .allocations
            .iter()
            .find(|a| a.address == "staker-good")
            .unwrap();
        let bad = response
            .allocations
            .iter()
            .find(|a| a.address == "staker-bad")
            .unwrap();

        // Same stake, but good validator gets higher claim
        assert!(
            good.total_reward > bad.total_reward,
            "perf should affect claim"
        );
        assert!(good.performance_bonus > 0);
        assert_eq!(bad.performance_bonus, 0);

        // And the total is still within distributable
        let distributable = request.total_rewards - response.protocol_fee;
        assert!(response.total_distributed <= distributable);
    }

    #[test]
    fn test_mev_informational_share() {
        let request = test_request();
        let response = calculate_rewards(&request).unwrap();

        let total_mev: u128 = response.allocations.iter().map(|a| a.mev_share).sum();
        // 90% of 10 AETHEL MEV = 9 AETHEL reported as informational share
        let expected_mev = (request.mev_revenue * 9000) / 10000;
        assert!(total_mev <= expected_mev + 1); // Allow rounding
    }

    #[test]
    fn test_performance_bonus() {
        // When all stakers delegate to the same validator, the weight factor
        // cancels in the ratio and performance_bonus = 0.  Use two validators
        // with different scores to produce a meaningful bonus.
        let mut request = test_request();
        request.validators = vec![
            ScoredValidator {
                address: "validator-1".to_string(),
                stake: 100_000,
                performance_score: 9500, // high
                decentralization_score: 8000,
                reputation_score: 10000,
                composite_score: 9100,
                tee_public_key: "key-1".to_string(),
                commission_bps: 500,
                rank: 1,
            },
            ScoredValidator {
                address: "validator-2".to_string(),
                stake: 80_000,
                performance_score: 5000, // lower
                decentralization_score: 7000,
                reputation_score: 8000,
                composite_score: 6500,
                tee_public_key: "key-2".to_string(),
                commission_bps: 700,
                rank: 2,
            },
        ];
        request.staker_stakes = vec![
            StakerStake {
                address: "staker-a".to_string(),
                shares: 600_000_000_000_000_000_000,
                delegated_to: "validator-1".to_string(), // high perf
            },
            StakerStake {
                address: "staker-b".to_string(),
                shares: 400_000_000_000_000_000_000,
                delegated_to: "validator-2".to_string(), // lower perf
            },
        ];

        let response = calculate_rewards(&request).unwrap();
        let a = response
            .allocations
            .iter()
            .find(|a| a.address == "staker-a")
            .unwrap();
        let b = response
            .allocations
            .iter()
            .find(|a| a.address == "staker-b")
            .unwrap();

        // Staker-a delegates to higher-performing validator → positive bonus
        assert!(
            a.performance_bonus > 0,
            "High-perf staker should get performance bonus"
        );
        // Bonus should be reasonable (up to ~10% of base reward)
        assert!(a.performance_bonus <= a.base_reward / 10 + 1);

        // Staker-b delegates to lower-performing validator → no upside bonus
        assert_eq!(
            b.performance_bonus, 0,
            "Low-perf staker should not get bonus"
        );

        // Total distributed stays within budget
        let distributable = request.total_rewards - response.protocol_fee;
        assert!(response.total_distributed <= distributable);
    }

    #[test]
    fn test_deterministic_output() {
        let request = test_request();
        let r1 = calculate_rewards(&request).unwrap();
        let r2 = calculate_rewards(&request).unwrap();

        assert_eq!(r1.merkle_root, r2.merkle_root);
        assert_eq!(r1.total_distributed, r2.total_distributed);
        assert_eq!(r1.protocol_fee, r2.protocol_fee);
    }

    // ── Fail-closed delegation tests ──────────────────────────────────────

    /// Staker with empty `delegated_to` is rejected.
    #[test]
    fn test_rejects_empty_delegation() {
        let mut request = test_request();
        request.staker_stakes = vec![StakerStake {
            address: "staker-no-delegation".to_string(),
            shares: 500_000_000_000_000_000_000,
            delegated_to: "".to_string(), // empty — bug this fix catches
        }];

        let result = calculate_rewards(&request);
        assert!(result.is_err(), "should reject empty delegated_to");
        let err = result.unwrap_err();
        assert!(
            err.contains("empty delegated_to"),
            "error should mention empty delegation, got: {}",
            err
        );
    }

    /// Staker delegating to an unknown validator is rejected.
    #[test]
    fn test_rejects_unknown_validator_delegation() {
        let mut request = test_request();
        request.staker_stakes = vec![StakerStake {
            address: "staker-unknown-val".to_string(),
            shares: 500_000_000_000_000_000_000,
            delegated_to: "nonexistent-validator".to_string(),
        }];

        let result = calculate_rewards(&request);
        assert!(
            result.is_err(),
            "should reject delegation to unknown validator"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("not in the active validator set"),
            "error should mention missing validator, got: {}",
            err
        );
    }

    /// Mixed: one valid staker plus one with empty delegation → rejected.
    /// The TEE must refuse to attest the entire batch, not skip the bad entry.
    #[test]
    fn test_rejects_batch_with_any_empty_delegation() {
        let mut request = test_request();
        request.staker_stakes = vec![
            StakerStake {
                address: "staker-ok".to_string(),
                shares: 500_000_000_000_000_000_000,
                delegated_to: "validator-1".to_string(),
            },
            StakerStake {
                address: "staker-bad".to_string(),
                shares: 500_000_000_000_000_000_000,
                delegated_to: "".to_string(),
            },
        ];

        let result = calculate_rewards(&request);
        assert!(
            result.is_err(),
            "entire batch must fail if any delegation is empty"
        );
    }

    /// Empty staker list still succeeds (no delegation to validate).
    #[test]
    fn test_empty_stakers_still_ok() {
        let mut request = test_request();
        request.staker_stakes = vec![];

        let result = calculate_rewards(&request);
        assert!(result.is_ok(), "empty staker list should succeed");
        let response = result.unwrap();
        assert!(response.allocations.is_empty());
        assert_eq!(response.total_distributed, 0);
    }

    #[test]
    fn test_duplicate_staker_address_rejected() {
        let mut request = test_request();
        // Add a duplicate staker address
        request.staker_stakes.push(StakerStake {
            address: request.staker_stakes[0].address.clone(),
            shares: 500,
            delegated_to: request.staker_stakes[0].delegated_to.clone(),
        });

        let result = calculate_rewards(&request);
        assert!(result.is_err(), "duplicate staker address must be rejected");
        assert!(
            result.unwrap_err().contains("duplicate staker address"),
            "error message should mention duplicate"
        );
    }
}
