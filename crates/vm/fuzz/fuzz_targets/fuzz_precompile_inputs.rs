#![no_main]
//! Fuzz target for VM precompile inputs.
//!
//! Exercises every registered precompile (crypto, PQC, ZKP, TEE) with
//! arbitrary byte-slice inputs and varying gas limits. The precompile
//! implementations must never panic: they should return PrecompileError or
//! a failure ExecutionResult for invalid / adversarial inputs.

use libfuzzer_sys::fuzz_target;
use aethelred_vm::precompiles::{addresses, PrecompileRegistry};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let registry = PrecompileRegistry::new();

    // Use the first two bytes to select which precompile to exercise and
    // to derive a gas limit. The remaining bytes are the precompile input.
    let selector = data[0];
    let gas_byte = data[1];
    let input = &data[2..];

    // Gas limit ranges from 0 to ~16M, covering out-of-gas edge cases.
    let gas_limit = (gas_byte as u64) * 65536;

    // -----------------------------------------------------------------------
    // 1. Route to a specific precompile based on the selector byte
    // -----------------------------------------------------------------------
    let address = match selector % 16 {
        0 => addresses::SHA256,
        1 => addresses::IDENTITY,
        2 => addresses::ECDSA_RECOVER,
        3 => addresses::DILITHIUM_VERIFY,
        4 => addresses::DILITHIUM5_VERIFY,
        5 => addresses::KYBER_DECAPS,
        6 => addresses::KYBER1024_DECAPS,
        7 => addresses::HYBRID_VERIFY,
        8 => addresses::ZKP_VERIFY,
        9 => addresses::GROTH16_VERIFY,
        10 => addresses::PLONK_VERIFY,
        11 => addresses::EZKL_VERIFY,
        12 => addresses::HALO2_VERIFY,
        13 => addresses::TEE_VERIFY,
        14 => addresses::TEE_VERIFY_NITRO,
        15 => addresses::TEE_VERIFY_SGX,
        _ => unreachable!(),
    };

    // The execute call must never panic regardless of input content or gas.
    let _ = registry.execute(address, input, gas_limit);

    // -----------------------------------------------------------------------
    // 2. Also exercise the registry's own validation paths
    // -----------------------------------------------------------------------
    // is_precompile and info must never panic.
    let _ = registry.is_precompile(address);
    let _ = registry.info(address);

    // Try an address that is definitely not a precompile.
    let bogus_address = 0xDEAD_u64;
    let _ = registry.execute(bogus_address, input, gas_limit);
    assert!(!registry.is_precompile(bogus_address));

    // -----------------------------------------------------------------------
    // 3. Fuzz the word_gas_cost helper with arbitrary lengths
    // -----------------------------------------------------------------------
    let base = (data[0] as u64) * 10;
    let per_word = (gas_byte as u64) + 1;
    let _ = aethelred_vm::precompiles::word_gas_cost(base, per_word, input.len());

    // -----------------------------------------------------------------------
    // 4. Directly exercise individual crypto precompiles for coverage
    // -----------------------------------------------------------------------
    // SHA256 — accepts any input.
    let _ = registry.execute(addresses::SHA256, input, u64::MAX);

    // IDENTITY — accepts any input.
    let _ = registry.execute(addresses::IDENTITY, input, u64::MAX);

    // ECDSA recover — needs exactly 128 bytes, but must not panic on any size.
    let _ = registry.execute(addresses::ECDSA_RECOVER, input, u64::MAX);

    // Dilithium3 — needs msg_len header + pubkey + sig, must handle short input.
    let _ = registry.execute(addresses::DILITHIUM_VERIFY, input, u64::MAX);

    // Kyber768 — needs secret_key + ciphertext, must handle short input.
    let _ = registry.execute(addresses::KYBER_DECAPS, input, u64::MAX);

    // Hybrid verify — needs threat_level + msg_len + msg + pk + sig.
    let _ = registry.execute(addresses::HYBRID_VERIFY, input, u64::MAX);
});
