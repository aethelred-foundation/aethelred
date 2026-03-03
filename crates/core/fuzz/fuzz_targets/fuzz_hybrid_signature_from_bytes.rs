#![no_main]
//! Fuzz target for HybridSignature::from_bytes
//!
//! Tests that arbitrary byte inputs never cause panics, buffer overflows,
//! or undefined behavior in the hybrid signature deserialization path.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The deserialization must never panic regardless of input.
    // It is acceptable to return Err for malformed data.
    let _ = aethelred_core::crypto::HybridSignature::from_bytes(data);
});
