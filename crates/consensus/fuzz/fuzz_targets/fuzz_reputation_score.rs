#![no_main]
//! Fuzz target for reputation scoring with random validator histories.
//!
//! Constructs random compute job records and feeds them into the reputation
//! engine to ensure score calculations never panic, overflow, or produce
//! inconsistent state — regardless of input values.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (address) + 32 (job_id) + 8 (complexity) + 1 (method) + 8 (slot) + 1 (success) = 82 bytes
    if data.len() < 82 {
        return;
    }

    let mut address = [0u8; 32];
    address.copy_from_slice(&data[0..32]);

    let mut job_id = [0u8; 32];
    job_id.copy_from_slice(&data[32..64]);

    let complexity = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let method_byte = data[72];
    let mut slot_bytes = [0u8; 8];
    slot_bytes.copy_from_slice(&data[73..81]);
    let slot = u64::from_le_bytes(slot_bytes);
    let success = data[81] & 1 == 1;

    // Map method byte to VerificationMethod variants
    let method = match method_byte % 4 {
        0 => aethelred_consensus::traits::VerificationMethod::TeeAttestation,
        1 => aethelred_consensus::traits::VerificationMethod::ZkProof,
        2 => aethelred_consensus::traits::VerificationMethod::Hybrid,
        _ => aethelred_consensus::traits::VerificationMethod::ReExecution,
    };

    // Use devnet config with minimal constraints to exercise more code paths
    let config = aethelred_consensus::reputation::ReputationConfig::devnet();
    let engine = aethelred_consensus::reputation::ReputationEngine::new(config);
    engine.update_slot(slot);

    let model_hash = [0u8; 32];
    let input_hash = [0u8; 32];
    let output_hash = [0u8; 32];

    let job = aethelred_consensus::reputation::ComputeJobRecord::new(
        job_id,
        model_hash,
        input_hash,
        output_hash,
        complexity,
        method,
        slot,
        success,
    );

    // Record the job — may succeed or fail depending on fuzzed values
    let _ = engine.record_job(address, job);

    // Score must always be retrievable without panic
    let _score = engine.get_score(&address);

    // If we have more data, record additional jobs to stress multi-job scoring
    let remaining = &data[82..];
    let chunk_size = 41; // 32 (job_id) + 8 (complexity) + 1 (success)
    for chunk in remaining.chunks_exact(chunk_size) {
        let mut extra_job_id = [0u8; 32];
        extra_job_id.copy_from_slice(&chunk[0..32]);
        let extra_complexity = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        let extra_success = chunk[40] & 1 == 1;

        let extra_job = aethelred_consensus::reputation::ComputeJobRecord::new(
            extra_job_id,
            model_hash,
            input_hash,
            output_hash,
            extra_complexity,
            aethelred_consensus::traits::VerificationMethod::ZkProof,
            slot,
            extra_success,
        );

        let _ = engine.record_job(address, extra_job);
    }

    // Final score retrieval must not panic
    let _final_score = engine.get_score(&address);

    // Daily decay must not panic
    let _ = engine.apply_daily_decay(slot);
});
