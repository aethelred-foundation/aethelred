#![no_main]
//! Fuzz target for HybridPublicKey::from_bytes
//!
//! Tests that arbitrary byte inputs never cause panics in the
//! hybrid public key deserialization path.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aethelred_core::crypto::HybridPublicKey::from_bytes(data);
});
