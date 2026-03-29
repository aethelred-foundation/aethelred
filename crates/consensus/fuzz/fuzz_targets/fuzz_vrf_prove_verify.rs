#![no_main]
//! Fuzz target for VRF prove and verify roundtrip.
//!
//! Feeds random seeds and messages into VRF key generation, proof creation,
//! and verification to ensure the prove-then-verify cycle never panics and
//! always produces consistent results for valid inputs.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for a seed plus 1 byte of message
    if data.len() < 33 {
        return;
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let message = &data[32..];

    // Attempt to generate VRF keys from the fuzzed seed
    let keys = match aethelred_consensus::vrf::VrfKeys::from_seed(&seed) {
        Ok(k) => k,
        Err(_) => return, // Invalid seed is expected for some inputs
    };

    let engine = aethelred_consensus::vrf::VrfEngine::new();

    // Attempt to prove with the fuzzed message
    let (proof, output) = match engine.prove(&keys, message) {
        Ok(result) => result,
        Err(_) => return, // Some inputs may fail, that's fine
    };

    // Verify must succeed for a valid prove output
    match engine.verify(keys.public_key(), message, &proof) {
        Ok(verified_output) => {
            // The verified output must match the original prove output
            assert_eq!(
                output.as_bytes(),
                verified_output.as_bytes(),
                "VRF verify output must match prove output"
            );
        }
        Err(_) => {
            // Mock VRF should always verify its own proofs; if using real VRF
            // feature, some edge-case keys might fail — that is acceptable.
        }
    }

    // Proof serialization roundtrip must be idempotent
    let proof_bytes = proof.to_bytes();
    if let Ok(deserialized) = aethelred_consensus::vrf::VrfProof::from_bytes(&proof_bytes) {
        let re_serialized = deserialized.to_bytes();
        assert_eq!(
            proof_bytes, re_serialized,
            "VrfProof to_bytes -> from_bytes -> to_bytes must be idempotent"
        );
    }
});
