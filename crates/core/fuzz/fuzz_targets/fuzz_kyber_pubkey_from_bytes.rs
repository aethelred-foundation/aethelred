#![no_main]
//! Fuzz target for KyberPublicKey::from_bytes
//!
//! Tests that arbitrary byte inputs with all 3 Kyber security levels
//! never cause panics.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try all Kyber levels to maximize code coverage
    let _ = aethelred_core::crypto::kyber::KyberPublicKey::from_bytes(
        data,
        aethelred_core::crypto::kyber::KyberLevel::Kyber512,
    );
    let _ = aethelred_core::crypto::kyber::KyberPublicKey::from_bytes(
        data,
        aethelred_core::crypto::kyber::KyberLevel::Kyber768,
    );
    let _ = aethelred_core::crypto::kyber::KyberPublicKey::from_bytes(
        data,
        aethelred_core::crypto::kyber::KyberLevel::Kyber1024,
    );
});
