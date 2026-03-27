use criterion::{criterion_group, criterion_main, Criterion, black_box};

use aethelred_consensus::vrf::{VrfEngine, VrfKeys};
use aethelred_consensus::reputation::{
    ComputeJobRecord, ReputationConfig, ReputationEngine,
};
use aethelred_consensus::traits::VerificationMethod;

// =============================================================================
// VRF BENCHMARKS
// =============================================================================

fn bench_vrf_key_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("vrf");

    group.bench_function("key_generation", |b| {
        let mut counter: u64 = 0;
        b.iter(|| {
            // Use a deterministic seed derived from counter to avoid RNG overhead
            // in the benchmark measurement itself
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&counter.to_le_bytes());
            counter = counter.wrapping_add(1);
            let keys = VrfKeys::from_seed(black_box(&seed))
                .expect("key generation must succeed");
            black_box(keys.public_key());
        });
    });

    group.finish();
}

fn bench_vrf_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("vrf");

    let seed = [42u8; 32];
    let keys = VrfKeys::from_seed(&seed).expect("key generation must succeed");
    let engine = VrfEngine::new();
    let message = b"benchmark-vrf-prove-input-message-slot-12345";

    group.bench_function("prove", |b| {
        b.iter(|| {
            let result = engine.prove(black_box(&keys), black_box(message.as_slice()))
                .expect("prove must succeed");
            black_box(result);
        });
    });

    group.finish();
}

fn bench_vrf_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("vrf");

    let seed = [42u8; 32];
    let keys = VrfKeys::from_seed(&seed).expect("key generation must succeed");
    let engine = VrfEngine::new();
    let message = b"benchmark-vrf-verify-input-message-slot-12345";

    // Pre-generate proof for verification benchmark
    let (proof, _output) = engine.prove(&keys, message.as_slice())
        .expect("prove must succeed");
    let public_key = keys.public_key_bytes();

    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = engine.verify(
                black_box(&public_key),
                black_box(message.as_slice()),
                black_box(&proof),
            ).expect("verify must succeed");
            black_box(result);
        });
    });

    group.finish();
}

// =============================================================================
// REPUTATION BENCHMARKS
// =============================================================================

fn bench_reputation_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("reputation");

    let config = ReputationConfig::devnet();
    let address = [1u8; 32];
    let model_hash = [2u8; 32];
    let input_hash = [3u8; 32];
    let output_hash = [4u8; 32];

    group.bench_function("record_job", |b| {
        let mut slot: u64 = 1_000_000;

        b.iter(|| {
            // Create a fresh engine each iteration to avoid accumulation effects
            // that would change the benchmark profile over time
            let engine = ReputationEngine::new(config.clone());
            engine.update_slot(slot);

            let mut job_id = [0u8; 32];
            job_id[..8].copy_from_slice(&slot.to_le_bytes());

            let job = ComputeJobRecord::new(
                job_id,
                model_hash,
                input_hash,
                output_hash,
                black_box(1000),
                VerificationMethod::ZkProof,
                slot,
                true,
            );

            let result = engine.record_job(black_box(address), job)
                .expect("record_job must succeed");
            black_box(result);

            slot = slot.wrapping_add(1);
        });
    });

    // Benchmark score update with a pre-populated validator history
    group.bench_function("record_job_with_history", |b| {
        let engine = ReputationEngine::new(config.clone());
        let base_slot: u64 = 1_000_000;
        engine.update_slot(base_slot);

        // Pre-populate with 50 jobs to simulate a validator with history
        for i in 0..50u64 {
            let mut job_id = [0u8; 32];
            job_id[..8].copy_from_slice(&i.to_le_bytes());
            let job = ComputeJobRecord::new(
                job_id,
                model_hash,
                input_hash,
                output_hash,
                500 + (i % 10) * 100,
                VerificationMethod::TeeAttestation,
                base_slot.saturating_sub(i * 100),
                true,
            );
            let _ = engine.record_job(address, job);
        }

        let mut counter: u64 = 1000;

        b.iter(|| {
            let slot = base_slot + counter;
            engine.update_slot(slot);

            let mut job_id = [0u8; 32];
            job_id[..8].copy_from_slice(&counter.to_le_bytes());

            let job = ComputeJobRecord::new(
                job_id,
                model_hash,
                input_hash,
                output_hash,
                black_box(750),
                VerificationMethod::Hybrid,
                slot,
                true,
            );

            let result = engine.record_job(black_box(address), job)
                .expect("record_job must succeed");
            black_box(result);

            counter += 1;
        });
    });

    group.finish();
}

// =============================================================================
// CRITERION HARNESS
// =============================================================================

criterion_group!(
    benches,
    bench_vrf_key_generation,
    bench_vrf_prove,
    bench_vrf_verify,
    bench_reputation_update,
);
criterion_main!(benches);
