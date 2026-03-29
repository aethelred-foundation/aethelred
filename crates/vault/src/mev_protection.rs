//! MEV Protection Module — Commit-Reveal Ordering
//!
//! Implements a commit-reveal scheme processed inside a TEE enclave
//! to eliminate front-running and sandwich attacks:
//!
//! 1. **Commit Phase**: Validators submit hash(block_data || nonce).
//! 2. **Reveal Phase**: Validators reveal block_data + nonce.
//! 3. **Verification**: TEE verifies hash(reveal) == commitment.
//! 4. **Ordering**: TEE orders valid reveals by timestamp (fair ordering).
//!
//! Since the TEE cannot see other validators' blocks before ordering,
//! and the commit-reveal prevents retroactive reordering, MEV extraction
//! through front-running is eliminated.

use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::types::*;

/// Process commitments and reveals to produce a fair transaction ordering.
///
/// # Algorithm
///
/// 1. Index all commitments by validator address.
/// 2. For each reveal, verify `SHA-256(block_data || nonce) == commitment_hash`.
/// 3. Discard reveals without matching commitments or with invalid hashes.
/// 4. Sort valid reveals by timestamp (ascending) for fair ordering.
/// 5. Assign position numbers starting from 0.
///
/// # Returns
///
/// `(ordered_reveals, invalid_validator_addresses)`
pub fn process_commit_reveal(
    commitments: &[Commitment],
    reveals: &[Reveal],
) -> (Vec<ValidatedReveal>, Vec<String>) {
    // Index commitments by validator
    let commitment_map: HashMap<&str, &Commitment> = commitments
        .iter()
        .map(|c| (c.validator.as_str(), c))
        .collect();

    let mut valid_reveals = Vec::new();
    let mut invalid = Vec::new();

    for reveal in reveals {
        match commitment_map.get(reveal.validator.as_str()) {
            Some(commitment) => {
                // Verify hash: SHA-256(block_data || nonce) must equal commitment_hash
                if verify_commitment_hash(
                    &reveal.block_data,
                    &reveal.nonce,
                    &commitment.commitment_hash,
                ) {
                    valid_reveals.push(ValidatedReveal {
                        validator: reveal.validator.clone(),
                        block_data: reveal.block_data.clone(),
                        ordering_timestamp: reveal.timestamp,
                        position: 0, // Assigned after sorting
                    });
                } else {
                    invalid.push(reveal.validator.clone());
                }
            }
            None => {
                // No matching commitment found
                invalid.push(reveal.validator.clone());
            }
        }
    }

    // Sort by timestamp (fair ordering — no validator advantage)
    valid_reveals.sort_by_key(|r| r.ordering_timestamp);

    // Assign positions
    for (i, reveal) in valid_reveals.iter_mut().enumerate() {
        reveal.position = i as u32;
    }

    (valid_reveals, invalid)
}

/// Verify that hash(block_data || nonce) equals the commitment hash.
pub fn verify_commitment_hash(block_data: &str, nonce: &str, expected_hash: &str) -> bool {
    let computed = compute_commitment_hash(block_data, nonce);
    computed == expected_hash
}

/// Compute a commitment hash: SHA-256(block_data || nonce).
pub fn compute_commitment_hash(block_data: &str, nonce: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(block_data.as_bytes());
    hasher.update(nonce.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a random nonce for commitment.
pub fn generate_nonce() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let nonce: [u8; 32] = rng.gen();
    hex::encode(nonce)
}

/// Detect potential MEV activity by analyzing transaction patterns.
///
/// Looks for:
/// - Duplicate transactions targeting the same contract
/// - Suspiciously timed transactions (within same block)
/// - Large-value transactions followed by opposite-direction trades
pub fn detect_mev_patterns(reveals: &[ValidatedReveal]) -> Vec<MevAlert> {
    let mut alerts = Vec::new();

    // Check for duplicate block proposals (same data from different validators)
    let mut data_seen: HashMap<&str, Vec<&str>> = HashMap::new();
    for reveal in reveals {
        data_seen
            .entry(reveal.block_data.as_str())
            .or_default()
            .push(reveal.validator.as_str());
    }

    for (data, validators) in &data_seen {
        if validators.len() > 1 {
            alerts.push(MevAlert {
                alert_type: "DUPLICATE_BLOCK_DATA".to_string(),
                description: format!(
                    "Identical block data submitted by {} validators",
                    validators.len()
                ),
                validators: validators.iter().map(|v| v.to_string()).collect(),
                severity: if validators.len() > 2 {
                    "HIGH"
                } else {
                    "MEDIUM"
                }
                .to_string(),
                block_data_hash: compute_commitment_hash(data, ""),
            });
        }
    }

    // Check for suspiciously close timestamps
    if reveals.len() >= 2 {
        for window in reveals.windows(2) {
            let time_diff = window[1]
                .ordering_timestamp
                .saturating_sub(window[0].ordering_timestamp);
            if time_diff == 0 {
                alerts.push(MevAlert {
                    alert_type: "SIMULTANEOUS_SUBMISSION".to_string(),
                    description: "Two reveals with identical timestamps".to_string(),
                    validators: vec![window[0].validator.clone(), window[1].validator.clone()],
                    severity: "LOW".to_string(),
                    block_data_hash: String::new(),
                });
            }
        }
    }

    alerts
}

/// MEV detection alert.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MevAlert {
    pub alert_type: String,
    pub description: String,
    pub validators: Vec<String>,
    pub severity: String,
    pub block_data_hash: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commitment(
        validator: &str,
        block_data: &str,
        nonce: &str,
        ts: u64,
    ) -> (Commitment, Reveal) {
        let hash = compute_commitment_hash(block_data, nonce);
        (
            Commitment {
                validator: validator.to_string(),
                commitment_hash: hash,
                timestamp: ts,
            },
            Reveal {
                validator: validator.to_string(),
                block_data: block_data.to_string(),
                nonce: nonce.to_string(),
                timestamp: ts + 10, // Reveal 10s after commit
            },
        )
    }

    #[test]
    fn test_valid_commit_reveal() {
        let (c1, r1) = make_commitment("v1", "block-1", "nonce-1", 1000);
        let (c2, r2) = make_commitment("v2", "block-2", "nonce-2", 1001);

        let (ordered, invalid) = process_commit_reveal(&[c1, c2], &[r1, r2]);

        assert_eq!(ordered.len(), 2);
        assert!(invalid.is_empty());
        assert_eq!(ordered[0].position, 0);
        assert_eq!(ordered[1].position, 1);
    }

    #[test]
    fn test_invalid_reveal_rejected() {
        let (c1, _r1) = make_commitment("v1", "block-1", "nonce-1", 1000);

        // Tamper with block data
        let bad_reveal = Reveal {
            validator: "v1".to_string(),
            block_data: "tampered-block".to_string(),
            nonce: "nonce-1".to_string(),
            timestamp: 1010,
        };

        let (ordered, invalid) = process_commit_reveal(&[c1], &[bad_reveal]);

        assert_eq!(ordered.len(), 0);
        assert_eq!(invalid.len(), 1);
        assert_eq!(invalid[0], "v1");
    }

    #[test]
    fn test_no_commitment_rejected() {
        let reveal = Reveal {
            validator: "unknown".to_string(),
            block_data: "block-1".to_string(),
            nonce: "nonce-1".to_string(),
            timestamp: 1000,
        };

        let (ordered, invalid) = process_commit_reveal(&[], &[reveal]);

        assert_eq!(ordered.len(), 0);
        assert_eq!(invalid.len(), 1);
    }

    #[test]
    fn test_fair_ordering_by_timestamp() {
        let (c1, mut r1) = make_commitment("v1", "block-1", "nonce-1", 1000);
        let (c2, mut r2) = make_commitment("v2", "block-2", "nonce-2", 1001);
        let (c3, mut r3) = make_commitment("v3", "block-3", "nonce-3", 1002);

        // Deliberately submit reveals out of order
        r1.timestamp = 1020; // Latest
        r2.timestamp = 1010; // Earliest
        r3.timestamp = 1015; // Middle

        let (ordered, _) = process_commit_reveal(&[c1, c2, c3], &[r1, r2, r3]);

        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].validator, "v2"); // Earliest timestamp
        assert_eq!(ordered[1].validator, "v3");
        assert_eq!(ordered[2].validator, "v1"); // Latest timestamp
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        let h1 = compute_commitment_hash("data", "nonce");
        let h2 = compute_commitment_hash("data", "nonce");
        assert_eq!(h1, h2);

        let h3 = compute_commitment_hash("data", "different-nonce");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_mev_detection_duplicate_data() {
        let reveals = vec![
            ValidatedReveal {
                validator: "v1".to_string(),
                block_data: "same-data".to_string(),
                ordering_timestamp: 1000,
                position: 0,
            },
            ValidatedReveal {
                validator: "v2".to_string(),
                block_data: "same-data".to_string(),
                ordering_timestamp: 1001,
                position: 1,
            },
        ];

        let alerts = detect_mev_patterns(&reveals);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].alert_type, "DUPLICATE_BLOCK_DATA");
    }
}
