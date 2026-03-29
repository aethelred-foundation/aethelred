// SQ14 — TEE Latency Baseline: Rust Benchmarks
//
// Benchmarks for TEE precompile execution, attestation structural validation,
// and measurement comparison in the Rust VM layer.
//
// Run:
//   cargo bench --manifest-path crates/vm/Cargo.toml --bench tee_bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ════════════════════════════════════════════════════════════════════════
// TEE Attestation Structural Validation Benchmarks
// ════════════════════════════════════════════════════════════════════════

/// Simulates SGX quote structural validation (minimum size check + non-zero).
fn sgx_quote_structural_validation(quote: &[u8]) -> bool {
    if quote.len() < 432 {
        return false;
    }
    // Check not all zeros (first 64 bytes).
    let check_len = std::cmp::min(64, quote.len());
    quote[..check_len].iter().any(|&b| b != 0)
}

/// Simulates Nitro attestation structural validation (CBOR envelope check).
fn nitro_attestation_structural_validation(attestation: &[u8]) -> bool {
    if attestation.len() < 1000 {
        return false;
    }
    // Check not all zeros.
    attestation.iter().take(64).any(|&b| b != 0)
}

/// Simulates SEV-SNP report structural validation.
fn sev_report_structural_validation(report: &[u8]) -> bool {
    if report.len() < 672 {
        return false;
    }
    report.iter().take(64).any(|&b| b != 0)
}

fn bench_attestation_structural_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("tee_attestation_structural_validation");

    // SGX quotes at various sizes.
    for size in [432, 1024, 2048, 4096] {
        let quote: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("SGX", size),
            &quote,
            |b, q| b.iter(|| sgx_quote_structural_validation(black_box(q))),
        );
    }

    // Nitro attestations.
    for size in [1000, 2048, 4096, 8192] {
        let att: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("Nitro", size),
            &att,
            |b, a| b.iter(|| nitro_attestation_structural_validation(black_box(a))),
        );
    }

    // SEV-SNP reports.
    for size in [672, 1024, 2048] {
        let report: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("SEV", size),
            &report,
            |b, r| b.iter(|| sev_report_structural_validation(black_box(r))),
        );
    }

    group.finish();
}

// ════════════════════════════════════════════════════════════════════════
// Measurement Comparison Benchmarks
// ════════════════════════════════════════════════════════════════════════

/// Linear scan measurement lookup (mirrors Go-side trusted measurement check).
fn measurement_lookup_linear(trusted: &[Vec<u8>], target: &[u8]) -> bool {
    trusted.iter().any(|m| m.as_slice() == target)
}

/// HashMap-based measurement lookup (optimized path).
fn measurement_lookup_hashmap(registry: &HashMap<Vec<u8>, bool>, target: &[u8]) -> bool {
    registry.contains_key(target)
}

fn bench_measurement_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("tee_measurement_comparison");

    for registry_size in [1, 10, 50, 100, 500] {
        // Build trusted measurements.
        let trusted: Vec<Vec<u8>> = (0..registry_size)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(format!("trusted-measurement-{}", i).as_bytes());
                hasher.finalize().to_vec()
            })
            .collect();

        // Build HashMap for optimized path.
        let registry: HashMap<Vec<u8>, bool> = trusted.iter().map(|m| (m.clone(), true)).collect();

        // Target is the last measurement (worst case for linear scan).
        let target = trusted.last().unwrap().clone();

        group.bench_with_input(
            BenchmarkId::new("linear_scan", registry_size),
            &(trusted.clone(), target.clone()),
            |b, (trusted, target)| b.iter(|| measurement_lookup_linear(black_box(trusted), black_box(target))),
        );

        group.bench_with_input(
            BenchmarkId::new("hashmap_lookup", registry_size),
            &(registry.clone(), target.clone()),
            |b, (reg, target)| b.iter(|| measurement_lookup_hashmap(black_box(reg), black_box(target))),
        );
    }

    group.finish();
}

// ════════════════════════════════════════════════════════════════════════
// TEE Precompile Input Encoding / Hashing Benchmarks
// ════════════════════════════════════════════════════════════════════════

/// Simulates the hash computation done during TEE verification (report data hash).
fn compute_report_data_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Simulates hex encoding of measurement for logging/events.
fn encode_measurement_hex(measurement: &[u8]) -> String {
    hex::encode(measurement)
}

fn bench_tee_precompile_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("tee_precompile_operations");

    // Report data hashing at various input sizes.
    for size in [32, 64, 256, 1024, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("report_data_hash", size),
            &data,
            |b, d| b.iter(|| compute_report_data_hash(black_box(d))),
        );
    }

    // Measurement hex encoding.
    for size in [32, 48, 64] {
        let measurement: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.bench_with_input(
            BenchmarkId::new("measurement_hex_encode", size),
            &measurement,
            |b, m| b.iter(|| encode_measurement_hex(black_box(m))),
        );
    }

    // JSON measurement config parsing (shared config format).
    let config_json = build_bench_measurement_config(5, 3);
    group.bench_function("config_json_parse", |b| {
        b.iter(|| {
            let _: serde_json::Value = serde_json::from_slice(black_box(&config_json)).unwrap();
        })
    });

    group.finish();
}

/// Builds a measurement config JSON for benchmarking.
fn build_bench_measurement_config(platforms: usize, measurements_per_field: usize) -> Vec<u8> {
    let mut measurements: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();

    for p in 0..platforms {
        let platform = format!("platform-{}", p);
        let mut fields: HashMap<String, Vec<String>> = HashMap::new();
        for f in 0..3 {
            let field = format!("field-{}", f);
            let values: Vec<String> = (0..measurements_per_field)
                .map(|v| {
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}:{}:{}", platform, field, v).as_bytes());
                    hex::encode(hasher.finalize())
                })
                .collect();
            fields.insert(field, values);
        }
        measurements.insert(platform, fields);
    }

    let config = serde_json::json!({
        "version": 1,
        "measurements": measurements,
        "min_quote_age_seconds": 300,
        "last_updated": "2026-03-28T00:00:00Z"
    });

    serde_json::to_vec(&config).unwrap()
}

// ════════════════════════════════════════════════════════════════════════
// Criterion Group Registration
// ════════════════════════════════════════════════════════════════════════

criterion_group!(
    benches,
    bench_attestation_structural_validation,
    bench_measurement_comparison,
    bench_tee_precompile_operations,
);
criterion_main!(benches);
