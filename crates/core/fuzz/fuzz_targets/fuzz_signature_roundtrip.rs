#![no_main]
//! Differential fuzz target: serialize → deserialize → serialize roundtrip
//!
//! Verifies that for any valid signature, the to_bytes → from_bytes → to_bytes
//! roundtrip produces identical output (idempotency property).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary data as a signature
    if let Ok(sig) = aethelred_core::crypto::HybridSignature::from_bytes(data) {
        // If parsing succeeds, roundtrip must be idempotent
        let serialized = sig.to_bytes();
        let round_tripped = aethelred_core::crypto::HybridSignature::from_bytes(&serialized)
            .expect("roundtrip deserialization must succeed");
        let serialized_again = round_tripped.to_bytes();

        assert_eq!(
            serialized, serialized_again,
            "to_bytes -> from_bytes -> to_bytes must be idempotent"
        );
    }
});
