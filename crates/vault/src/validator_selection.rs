//! TEE Validator Selection Algorithm
//!
//! Runs inside a Trusted Execution Environment to produce a provably fair
//! validator set. The algorithm scores validators on three axes:
//!
//! 1. **Performance** (40%) — Uptime, response latency, jobs completed
//! 2. **Decentralization** (30%) — Geographic diversity, operator uniqueness
//! 3. **Reputation** (30%) — Slashing history, historical reliability
//!
//! Anti-Sybil measures enforce per-operator and per-region caps to prevent
//! any single entity from dominating the validator set.

use std::collections::{HashMap, HashSet};

use crate::types::*;

/// Maximum score for any individual dimension (basis points).
const MAX_SCORE: u32 = 10_000;

/// Select validators from candidates using the TEE scoring algorithm.
///
/// # Algorithm
///
/// 1. Filter candidates below minimum thresholds (uptime, stake, commission).
/// 2. Score each candidate on performance, decentralization, and reputation.
/// 3. Compute weighted composite score.
/// 4. Apply diversity constraints (max per region, max per operator).
/// 5. Select top N validators by composite score.
///
/// # Returns
///
/// A `Vec<ScoredValidator>` sorted by composite score (descending),
/// containing at most `target_count` validators.
pub fn select_validators(
    candidates: &[ValidatorInput],
    target_count: usize,
    config: &SelectionConfig,
) -> Vec<ScoredValidator> {
    // Phase 0: Defensive dedup by address (first occurrence wins).
    //
    // The handler already rejects duplicate candidates with 400, but we
    // enforce uniqueness here too for defense-in-depth so that the core
    // algorithm can never produce a duplicate-filled validator set even if
    // called from test harnesses or future callers that skip input validation.
    let mut seen_addrs = HashSet::with_capacity(candidates.len());
    let deduped: Vec<&ValidatorInput> = candidates
        .iter()
        .filter(|v| seen_addrs.insert(&v.address))
        .collect();

    // Phase 1: Filter ineligible candidates
    let eligible: Vec<&ValidatorInput> = deduped
        .into_iter()
        .filter(|v| {
            v.uptime_pct >= config.min_uptime_pct
                && v.commission_bps <= config.max_commission_bps
                && v.stake >= config.min_stake
        })
        .collect();

    if eligible.is_empty() {
        return Vec::new();
    }

    // Precompute decentralization context
    let region_counts = count_by_field(&eligible, |v| v.geographic_region.clone());
    let total_regions = region_counts.len() as f64;

    // Phase 2: Score each candidate
    let mut scored: Vec<ScoredValidator> = eligible
        .iter()
        .map(|v| {
            let perf = performance_score(v);
            let decent = decentralization_score(v, &region_counts, total_regions);
            let rep = reputation_score(v);

            let composite = weighted_composite(
                perf,
                decent,
                rep,
                config.performance_weight,
                config.decentralization_weight,
                config.reputation_weight,
            );

            ScoredValidator {
                address: v.address.clone(),
                stake: v.stake,
                performance_score: perf,
                decentralization_score: decent,
                reputation_score: rep,
                composite_score: composite,
                tee_public_key: v.tee_public_key.clone(),
                commission_bps: v.commission_bps,
                rank: 0,
            }
        })
        .collect();

    // Phase 3: Sort by composite score (descending)
    scored.sort_by(|a, b| b.composite_score.cmp(&a.composite_score));

    // Phase 4: Apply diversity constraints
    let selected = apply_diversity_constraints(
        scored,
        target_count,
        config.max_per_region,
        config.max_per_operator,
        candidates,
    );

    // Phase 5: Assign ranks
    selected
        .into_iter()
        .enumerate()
        .map(|(i, mut v)| {
            v.rank = (i + 1) as u32;
            v
        })
        .collect()
}

/// Calculate performance score (0–10000 basis points).
///
/// Components:
/// - Uptime: 50% weight (linear scale from min_uptime to 100%)
/// - Response latency: 30% weight (inverse scale, lower is better)
/// - Jobs completed: 20% weight (logarithmic scale)
fn performance_score(v: &ValidatorInput) -> u32 {
    // Uptime component (50%)
    let uptime_normalized = ((v.uptime_pct - 95.0) / 5.0).clamp(0.0, 1.0);
    let uptime_score = (uptime_normalized * 5000.0) as u32;

    // Latency component (30%) — target: 50ms, worst: 500ms
    let latency_normalized = 1.0 - ((v.avg_response_ms - 50.0) / 450.0).clamp(0.0, 1.0);
    let latency_score = (latency_normalized * 3000.0) as u32;

    // Jobs completed component (20%) — logarithmic scale
    let jobs_log = (1.0 + v.total_jobs_completed as f64).ln() / (1.0 + 100_000.0_f64).ln();
    let jobs_score = (jobs_log.clamp(0.0, 1.0) * 2000.0) as u32;

    (uptime_score + latency_score + jobs_score).min(MAX_SCORE)
}

/// Calculate decentralization score (0–10000 basis points).
///
/// Components:
/// - Geographic rarity: 60% weight (rarer regions score higher)
/// - Region diversity bonus: 40% weight (bonus for underrepresented regions)
fn decentralization_score(
    v: &ValidatorInput,
    region_counts: &HashMap<String, usize>,
    total_regions: f64,
) -> u32 {
    let region_count = *region_counts.get(&v.geographic_region).unwrap_or(&1) as f64;
    let total_validators = region_counts.values().sum::<usize>() as f64;

    // Geographic rarity (60%): inverse of region concentration
    let concentration = region_count / total_validators;
    let rarity = 1.0 - concentration;
    let rarity_score = (rarity * 6000.0) as u32;

    // Region diversity bonus (40%): bonus for regions with few validators
    let diversity_bonus = if region_count <= 2.0 {
        4000 // Full bonus for rare regions
    } else if region_count <= 5.0 {
        2000 // Half bonus
    } else {
        // Diminishing returns based on total regions
        ((total_regions / (region_count + total_regions)) * 4000.0) as u32
    };

    (rarity_score + diversity_bonus).min(MAX_SCORE)
}

/// Calculate reputation score (0–10000 basis points).
///
/// Components:
/// - Slashing history: 70% weight (exponential penalty per slash)
/// - Track record: 30% weight (based on time active and consistency)
fn reputation_score(v: &ValidatorInput) -> u32 {
    // Slashing penalty (70%): exponential decay per slash event
    let slash_penalty = 1.0 / (1.0 + v.slash_count as f64 * 2.0);
    let slash_score = (slash_penalty * 7000.0) as u32;

    // Track record (30%): based on jobs completed relative to slashes
    let reliability = if v.total_jobs_completed == 0 {
        0.5 // Neutral for new validators
    } else {
        
        v.total_jobs_completed as f64 / (v.total_jobs_completed as f64 + v.slash_count as f64)
    };
    let track_score = (reliability * 3000.0) as u32;

    (slash_score + track_score).min(MAX_SCORE)
}

/// Compute weighted composite score.
fn weighted_composite(
    perf: u32,
    decent: u32,
    rep: u32,
    perf_weight: f64,
    decent_weight: f64,
    rep_weight: f64,
) -> u32 {
    let composite =
        perf as f64 * perf_weight + decent as f64 * decent_weight + rep as f64 * rep_weight;
    (composite as u32).min(MAX_SCORE)
}

/// Apply diversity constraints to prevent centralization.
///
/// Enforces:
/// - Maximum validators per geographic region
/// - Maximum validators per operator
fn apply_diversity_constraints(
    scored: Vec<ScoredValidator>,
    target_count: usize,
    max_per_region: usize,
    max_per_operator: usize,
    candidates: &[ValidatorInput],
) -> Vec<ScoredValidator> {
    // Build address-to-candidate lookup
    let candidate_map: HashMap<String, &ValidatorInput> =
        candidates.iter().map(|v| (v.address.clone(), v)).collect();

    let mut region_count: HashMap<String, usize> = HashMap::new();
    let mut operator_count: HashMap<String, usize> = HashMap::new();
    let mut selected_addrs: HashSet<String> = HashSet::with_capacity(target_count);
    let mut selected = Vec::with_capacity(target_count);

    for validator in scored {
        if selected.len() >= target_count {
            break;
        }

        // Skip duplicate addresses (defense-in-depth; Phase 0 dedup should
        // have already eliminated these, but belt-and-suspenders).
        if selected_addrs.contains(&validator.address) {
            continue;
        }

        if let Some(candidate) = candidate_map.get(&validator.address) {
            // Check region cap (0 = dynamic limit based on target/regions)
            let effective_max_region = if max_per_region == 0 {
                // Dynamic: allow up to 40% of target in any single region
                (target_count * 2 / 5).max(2)
            } else {
                max_per_region
            };

            let region = &candidate.geographic_region;
            let region_n = region_count.get(region).copied().unwrap_or(0);
            if region_n >= effective_max_region {
                continue;
            }

            // Check operator cap
            let operator = &candidate.operator_id;
            let operator_n = operator_count.get(operator).copied().unwrap_or(0);
            if operator_n >= max_per_operator {
                continue;
            }

            *region_count.entry(region.clone()).or_insert(0) += 1;
            *operator_count.entry(operator.clone()).or_insert(0) += 1;
            selected_addrs.insert(validator.address.clone());
            selected.push(validator);
        }
    }

    selected
}

/// Count items by a key function.
fn count_by_field<T, F: Fn(&T) -> String>(items: &[&T], key_fn: F) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for item in items {
        *counts.entry(key_fn(item)).or_insert(0) += 1;
    }
    counts
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator(
        addr: &str,
        region: &str,
        uptime: f64,
        latency: f64,
        slashes: u32,
    ) -> ValidatorInput {
        ValidatorInput {
            address: addr.to_string(),
            stake: 100_000_000_000_000_000_000, // 100 AETHEL
            uptime_pct: uptime,
            avg_response_ms: latency,
            geographic_region: region.to_string(),
            country_code: "US".to_string(),
            operator_id: format!("op-{addr}"),
            slash_count: slashes,
            total_jobs_completed: 1000,
            tee_public_key: format!("key-{addr}"),
            commission_bps: 500,
        }
    }

    #[test]
    fn test_basic_selection() {
        let candidates = vec![
            test_validator("v1", "us-east", 99.9, 50.0, 0),
            test_validator("v2", "eu-west", 99.5, 80.0, 0),
            test_validator("v3", "ap-south", 98.0, 120.0, 1),
            test_validator("v4", "us-west", 97.0, 150.0, 0),
            test_validator("v5", "eu-central", 99.8, 60.0, 0),
        ];

        let config = SelectionConfig::default();
        let selected = select_validators(&candidates, 4, &config);

        assert_eq!(selected.len(), 4);
        assert!(selected[0].composite_score >= selected[1].composite_score);
        assert_eq!(selected[0].rank, 1);
    }

    #[test]
    fn test_filters_low_uptime() {
        let candidates = vec![
            test_validator("v1", "us-east", 99.9, 50.0, 0),
            test_validator("v2", "eu-west", 90.0, 80.0, 0), // Below 95% minimum
        ];

        let config = SelectionConfig::default();
        let selected = select_validators(&candidates, 4, &config);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].address, "v1");
    }

    #[test]
    fn test_diversity_enforcement() {
        // Create 6 validators, 4 in the same region
        let candidates = vec![
            test_validator("v1", "us-east", 99.9, 50.0, 0),
            test_validator("v2", "us-east", 99.8, 55.0, 0),
            test_validator("v3", "us-east", 99.7, 60.0, 0),
            test_validator("v4", "us-east", 99.6, 65.0, 0),
            test_validator("v5", "eu-west", 99.5, 70.0, 0),
            test_validator("v6", "ap-south", 99.4, 75.0, 0),
        ];

        let config = SelectionConfig {
            max_per_region: 2,
            ..Default::default()
        };
        let selected = select_validators(&candidates, 4, &config);

        // Should have max 2 from us-east
        let us_east_count = selected
            .iter()
            .filter(|v| {
                candidates
                    .iter()
                    .find(|c| c.address == v.address)
                    .map_or(false, |c| c.geographic_region == "us-east")
            })
            .count();

        assert!(us_east_count <= 2);
    }

    #[test]
    fn test_operator_cap() {
        let mut candidates = vec![
            test_validator("v1", "us-east", 99.9, 50.0, 0),
            test_validator("v2", "eu-west", 99.8, 55.0, 0),
            test_validator("v3", "ap-south", 99.7, 60.0, 0),
            test_validator("v4", "us-west", 99.6, 65.0, 0),
        ];
        // Make v1-v4 all same operator
        for c in &mut candidates {
            c.operator_id = "same-operator".to_string();
        }

        let config = SelectionConfig {
            max_per_operator: 2,
            ..Default::default()
        };
        let selected = select_validators(&candidates, 4, &config);

        assert!(selected.len() <= 2);
    }

    #[test]
    fn test_slashing_penalty() {
        let candidates = vec![
            test_validator("good", "us-east", 99.9, 50.0, 0),
            test_validator("bad", "eu-west", 99.9, 50.0, 5),
        ];

        let config = SelectionConfig::default();
        let selected = select_validators(&candidates, 2, &config);

        assert_eq!(selected.len(), 2);
        // Good validator should rank higher
        assert_eq!(selected[0].address, "good");
        assert!(selected[0].reputation_score > selected[1].reputation_score);
    }

    #[test]
    fn test_empty_candidates() {
        let candidates = vec![];
        let config = SelectionConfig::default();
        let selected = select_validators(&candidates, 4, &config);
        assert!(selected.is_empty());
    }

    #[test]
    fn test_performance_score_calculation() {
        let v = test_validator("v1", "us-east", 100.0, 50.0, 0);
        let score = performance_score(&v);
        assert!(score > 8000); // High uptime + low latency should score well
    }

    #[test]
    fn test_duplicate_addresses_rejected() {
        // Duplicate candidate addresses must not produce duplicate slots
        // in the selected set, even if the same address appears multiple
        // times in the input with different scores.
        let mut v1a = test_validator("v1", "us-east", 99.9, 50.0, 0);
        let mut v1b = test_validator("v1", "eu-west", 99.5, 80.0, 0);
        // Give the duplicate a different operator so it wouldn't be caught
        // by operator-cap alone.
        v1a.operator_id = "op-a".to_string();
        v1b.operator_id = "op-b".to_string();
        let v2 = test_validator("v2", "ap-south", 98.0, 120.0, 1);
        let v3 = test_validator("v3", "us-west", 97.0, 150.0, 0);

        let candidates = vec![v1a, v1b, v2, v3];
        let config = SelectionConfig::default();
        let selected = select_validators(&candidates, 4, &config);

        // v1 should appear at most once
        let v1_count = selected.iter().filter(|v| v.address == "v1").count();
        assert_eq!(
            v1_count, 1,
            "duplicate address 'v1' must appear at most once"
        );

        // All selected addresses must be unique
        let addrs: HashSet<&str> = selected.iter().map(|v| v.address.as_str()).collect();
        assert_eq!(
            addrs.len(),
            selected.len(),
            "all selected addresses must be unique"
        );
    }

    #[test]
    fn test_reputation_new_validator() {
        let mut v = test_validator("v1", "us-east", 99.9, 50.0, 0);
        v.total_jobs_completed = 0;
        let score = reputation_score(&v);
        assert!(score > 5000); // New validator gets neutral reputation
    }
}
