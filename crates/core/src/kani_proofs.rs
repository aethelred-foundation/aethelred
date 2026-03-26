//! Kani formal verification proof harnesses for aethelred-core.
//!
//! These harnesses use the Kani model checker to formally verify safety
//! properties of core cryptographic and serialization primitives.
//!
//! Run with: `cargo kani --manifest-path crates/core/Cargo.toml`

use super::*;

// =============================================================================
// SignatureAlgorithm proofs
// =============================================================================

/// Proves that `SignatureAlgorithm::from_byte` roundtrips with `to_byte`
/// for all valid algorithm byte values.
#[kani::proof]
fn verify_signature_algorithm_roundtrip() {
    let byte: u8 = kani::any();

    if let Some(alg) = crypto::SignatureAlgorithm::from_byte(byte) {
        let roundtripped = alg.to_byte();
        assert!(
            roundtripped == byte,
            "SignatureAlgorithm roundtrip must preserve the byte value"
        );

        // Also verify from_byte on the roundtripped value gives back the same variant
        let alg2 = crypto::SignatureAlgorithm::from_byte(roundtripped).unwrap();
        assert!(
            alg == alg2,
            "Double roundtrip must produce the same algorithm"
        );
    }
}

/// Proves that `signature_size()` is always > 0 for any valid algorithm,
/// and that `public_key_size()` is always > 0.
#[kani::proof]
fn verify_signature_and_pubkey_sizes_positive() {
    let byte: u8 = kani::any();

    if let Some(alg) = crypto::SignatureAlgorithm::from_byte(byte) {
        assert!(
            alg.signature_size() > 0,
            "Signature size must be positive"
        );
        assert!(
            alg.public_key_size() > 0,
            "Public key size must be positive"
        );
    }
}

/// Proves that quantum-safe classification is consistent:
/// only EcdsaSecp256k1 is NOT quantum-safe among valid algorithms.
#[kani::proof]
fn verify_quantum_safety_classification() {
    let byte: u8 = kani::any();

    if let Some(alg) = crypto::SignatureAlgorithm::from_byte(byte) {
        match alg {
            crypto::SignatureAlgorithm::EcdsaSecp256k1 => {
                assert!(
                    !alg.is_quantum_safe(),
                    "ECDSA must not be classified as quantum-safe"
                );
            }
            _ => {
                assert!(
                    alg.is_quantum_safe(),
                    "Dilithium3, Dilithium5, and Hybrid must be quantum-safe"
                );
            }
        }
    }
}

// =============================================================================
// QuantumThreatLevel proofs
// =============================================================================

/// Proves monotonicity properties of QuantumThreatLevel:
/// - skip_classical implies classical_optional
/// - quantum_only implies skip_classical
#[kani::proof]
fn verify_quantum_threat_level_monotonicity() {
    let level: u8 = kani::any();
    let qtl = crypto::QuantumThreatLevel(level);

    // quantum_only => skip_classical
    if qtl.quantum_only() {
        assert!(
            qtl.skip_classical(),
            "quantum_only must imply skip_classical"
        );
    }

    // skip_classical => classical_optional
    if qtl.skip_classical() {
        assert!(
            qtl.classical_optional(),
            "skip_classical must imply classical_optional"
        );
    }
}

// =============================================================================
// Serde byte array proofs
// =============================================================================

/// Proves that the Hash256::from_slice function correctly rejects
/// slices of any length other than 32.
#[kani::proof]
fn verify_hash256_from_slice_length_check() {
    // Test with a bounded length to keep verification tractable
    let len: usize = kani::any();
    kani::assume(len <= 64);

    let data = vec![0u8; len];
    let result = crypto::hash::Hash256::from_slice(&data);

    if len == crypto::hash::HASH_SIZE_256 {
        assert!(result.is_some(), "from_slice must succeed for 32-byte input");
    } else {
        assert!(result.is_none(), "from_slice must fail for non-32-byte input");
    }
}
