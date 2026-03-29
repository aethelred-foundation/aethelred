//! SQ15 — zkML Latency and Cost Optimization: Rust-side precompile benchmarks
//!
//! Benchmarks the unified 0x0300 ZKP_VERIFY precompile and each proof-system-specific
//! precompile (Groth16, PLONK, EZKL, Halo2, STARK) to establish a cost baseline.
//!
//! Run:
//!   cargo bench --manifest-path crates/Cargo.toml -p aethelred-vm --bench zkml_precompile_bench
//!
//! NOTE: Without the `zkp` feature (arkworks), Groth16/PLONK verification falls back
//! to structural validation. This benchmark captures the *precompile dispatch overhead*
//! and *encoding cost*; full cryptographic verification benchmarks require `--features zkp`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// We reference the precompiles module through the crate's public API.
use aethelred_vm::precompiles::{
    addresses, gas_costs, Precompile, PrecompileRegistry,
};

// ---------------------------------------------------------------------------
// Input builders
// ---------------------------------------------------------------------------

/// Build a valid-structure Groth16 input: [vk:544][proof:192][public_inputs:N*32]
fn make_groth16_input(num_public_inputs: usize) -> Vec<u8> {
    let vk_size = 544; // BN254 verifying key
    let proof_size = 192; // 2 G1 + 1 G2
    let pi_size = num_public_inputs * 32;
    let total = vk_size + proof_size + pi_size;

    let mut input = vec![0xABu8; total];
    // Fill with deterministic pattern for reproducibility
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    input
}

/// Build a PLONK input: [proof_size:4][vk_hash:32][num_inputs:4][public_inputs...][proof...]
fn make_plonk_input(proof_len: usize, num_public_inputs: usize) -> Vec<u8> {
    let pi_size = num_public_inputs * 32;
    let total = 4 + 32 + 4 + pi_size + proof_len;
    let mut input = vec![0u8; total];

    // proof_size (LE)
    let ps = (proof_len as u32).to_le_bytes();
    input[0..4].copy_from_slice(&ps);
    // vk_hash
    for i in 4..36 {
        input[i] = (i % 256) as u8;
    }
    // num_inputs (LE)
    let ni = (num_public_inputs as u32).to_le_bytes();
    input[36..40].copy_from_slice(&ni);
    // Fill rest with pattern
    for i in 40..total {
        input[i] = (i % 256) as u8;
    }
    input
}

/// Build an EZKL input: [model_hash:32][num_inputs:4][public_inputs...][proof...]
fn make_ezkl_input(proof_len: usize, num_public_inputs: usize) -> Vec<u8> {
    let pi_size = num_public_inputs * 32;
    let total = 32 + 4 + pi_size + proof_len;
    let mut input = vec![0u8; total];

    // model_hash
    for i in 0..32 {
        input[i] = (i % 256) as u8;
    }
    // num_inputs (LE)
    let ni = (num_public_inputs as u32).to_le_bytes();
    input[32..36].copy_from_slice(&ni);
    // Fill rest
    for i in 36..total {
        input[i] = (i % 256) as u8;
    }
    input
}

/// Build a Halo2 input: [circuit_params_hash:32][num_inputs:4][public_inputs...][proof...]
fn make_halo2_input(proof_len: usize, num_public_inputs: usize) -> Vec<u8> {
    // Same layout as EZKL for benchmarking purposes
    make_ezkl_input(proof_len, num_public_inputs)
}

/// Build a STARK (FRI-based) input of specified size
fn make_stark_input(total_size: usize) -> Vec<u8> {
    let mut input = vec![0u8; total_size];
    for (i, byte) in input.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }
    input
}

/// Build a unified 0x0300 input: [proof_system_id:1][inner_input...]
fn make_unified_input(system_id: u8, inner: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(1 + inner.len());
    input.push(system_id);
    input.extend_from_slice(inner);
    input
}

// ---------------------------------------------------------------------------
// Benchmark: per-system precompile execution via 0x0300 unified entry
// ---------------------------------------------------------------------------

fn bench_unified_precompile_per_system(c: &mut Criterion) {
    let registry = PrecompileRegistry::new();
    let gas_limit = 10_000_000u64;

    let mut group = c.benchmark_group("unified_0x0300_verify");

    // Groth16 (system_id=1) — 1 public input
    let groth16_inner = make_groth16_input(1);
    group.throughput(Throughput::Bytes(groth16_inner.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("Groth16", groth16_inner.len()),
        &groth16_inner,
        |b, inner| {
            let input = make_unified_input(0x01, inner);
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::ZKP_VERIFY, &input, gas_limit));
            });
        },
    );

    // PLONK (system_id=2)
    let plonk_inner = make_plonk_input(512, 2);
    group.bench_with_input(
        BenchmarkId::new("PLONK", plonk_inner.len()),
        &plonk_inner,
        |b, inner| {
            let input = make_unified_input(0x02, inner);
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::ZKP_VERIFY, &input, gas_limit));
            });
        },
    );

    // EZKL (system_id=3)
    let ezkl_inner = make_ezkl_input(1024, 4);
    group.bench_with_input(
        BenchmarkId::new("EZKL", ezkl_inner.len()),
        &ezkl_inner,
        |b, inner| {
            let input = make_unified_input(0x03, inner);
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::ZKP_VERIFY, &input, gas_limit));
            });
        },
    );

    // Halo2 (system_id=4)
    let halo2_inner = make_halo2_input(2048, 4);
    group.bench_with_input(
        BenchmarkId::new("Halo2", halo2_inner.len()),
        &halo2_inner,
        |b, inner| {
            let input = make_unified_input(0x04, inner);
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::ZKP_VERIFY, &input, gas_limit));
            });
        },
    );

    // STARK (system_id=5)
    let stark_inner = make_stark_input(4096);
    group.bench_with_input(
        BenchmarkId::new("STARK", stark_inner.len()),
        &stark_inner,
        |b, inner| {
            let input = make_unified_input(0x05, inner);
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::ZKP_VERIFY, &input, gas_limit));
            });
        },
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: direct precompile execution (bypasses 0x0300 routing)
// ---------------------------------------------------------------------------

fn bench_direct_precompile_execution(c: &mut Criterion) {
    let registry = PrecompileRegistry::new();
    let gas_limit = 10_000_000u64;

    let mut group = c.benchmark_group("direct_precompile_verify");

    // Groth16 direct at 0x0301
    let groth16_input = make_groth16_input(1);
    group.bench_with_input(
        BenchmarkId::new("Groth16_0x0301", groth16_input.len()),
        &groth16_input,
        |b, input| {
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::GROTH16_VERIFY, input, gas_limit));
            });
        },
    );

    // PLONK direct at 0x0302
    let plonk_input = make_plonk_input(512, 2);
    group.bench_with_input(
        BenchmarkId::new("PLONK_0x0302", plonk_input.len()),
        &plonk_input,
        |b, input| {
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::PLONK_VERIFY, input, gas_limit));
            });
        },
    );

    // EZKL direct at 0x0303
    let ezkl_input = make_ezkl_input(1024, 4);
    group.bench_with_input(
        BenchmarkId::new("EZKL_0x0303", ezkl_input.len()),
        &ezkl_input,
        |b, input| {
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::EZKL_VERIFY, input, gas_limit));
            });
        },
    );

    // Halo2 direct at 0x0304
    let halo2_input = make_halo2_input(2048, 4);
    group.bench_with_input(
        BenchmarkId::new("Halo2_0x0304", halo2_input.len()),
        &halo2_input,
        |b, input| {
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::HALO2_VERIFY, input, gas_limit));
            });
        },
    );

    // STARK direct at 0x0306
    let stark_input = make_stark_input(4096);
    group.bench_with_input(
        BenchmarkId::new("STARK_0x0306", stark_input.len()),
        &stark_input,
        |b, input| {
            b.iter(|| {
                let _ = black_box(registry.execute(addresses::STARK_VERIFY, input, gas_limit));
            });
        },
    );

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: proof encoding cost per proof system
// ---------------------------------------------------------------------------

fn bench_proof_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_encoding");

    let proof_configs: Vec<(&str, usize, usize)> = vec![
        ("Groth16_192B_1pi", 192, 1),
        ("Groth16_192B_4pi", 192, 4),
        ("PLONK_512B_2pi", 512, 2),
        ("EZKL_1KB_4pi", 1024, 4),
        ("EZKL_4KB_8pi", 4096, 8),
        ("Halo2_2KB_4pi", 2048, 4),
        ("STARK_4KB", 4096, 0),
        ("STARK_16KB", 16384, 0),
    ];

    for (name, proof_size, num_pi) in &proof_configs {
        let total_size = *proof_size + num_pi * 32 + 64; // approximate overhead
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new(*name, total_size),
            &(*proof_size, *num_pi),
            |b, &(ps, npi)| {
                b.iter(|| {
                    let input = if ps == 192 {
                        black_box(make_groth16_input(npi))
                    } else if npi == 0 {
                        black_box(make_stark_input(ps))
                    } else {
                        black_box(make_ezkl_input(ps, npi))
                    };
                    black_box(input);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: gas cost computation
// ---------------------------------------------------------------------------

fn bench_gas_computation(c: &mut Criterion) {
    let registry = PrecompileRegistry::new();

    let mut group = c.benchmark_group("gas_cost_computation");

    let systems: Vec<(&str, u64, Vec<u8>)> = vec![
        ("Groth16", addresses::GROTH16_VERIFY, make_groth16_input(1)),
        ("PLONK", addresses::PLONK_VERIFY, make_plonk_input(512, 2)),
        ("EZKL", addresses::EZKL_VERIFY, make_ezkl_input(1024, 4)),
        ("Halo2", addresses::HALO2_VERIFY, make_halo2_input(2048, 4)),
        ("STARK", addresses::STARK_VERIFY, make_stark_input(4096)),
    ];

    for (name, addr, input) in &systems {
        group.bench_with_input(
            BenchmarkId::new(*name, input.len()),
            input,
            |b, input| {
                let precompile = registry.get(*addr).unwrap();
                b.iter(|| {
                    black_box(precompile.gas_cost(black_box(input)));
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark: registry lookup
// ---------------------------------------------------------------------------

fn bench_registry_lookup(c: &mut Criterion) {
    let registry = PrecompileRegistry::new();

    let mut group = c.benchmark_group("registry_lookup");

    let addrs: Vec<(&str, u64)> = vec![
        ("ZKP_VERIFY_0x0300", addresses::ZKP_VERIFY),
        ("GROTH16_0x0301", addresses::GROTH16_VERIFY),
        ("PLONK_0x0302", addresses::PLONK_VERIFY),
        ("EZKL_0x0303", addresses::EZKL_VERIFY),
        ("HALO2_0x0304", addresses::HALO2_VERIFY),
        ("STARK_0x0306", addresses::STARK_VERIFY),
    ];

    for (name, addr) in &addrs {
        group.bench_function(*name, |b| {
            b.iter(|| {
                let _ = black_box(registry.get(black_box(*addr)));
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion groups
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_unified_precompile_per_system,
    bench_direct_precompile_execution,
    bench_proof_encoding,
    bench_gas_computation,
    bench_registry_lookup,
);

criterion_main!(benches);
