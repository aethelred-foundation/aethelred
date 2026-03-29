//! Inference benchmarks using criterion.
//!
//! These benchmarks measure the performance of AI/ML inference operations
//! including latency profiling and batch performance.

use aethelred_benchmarks::inference::{InferenceBenchmark, InferenceConfig};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn inference_latency_bench(c: &mut Criterion) {
    let config = InferenceConfig {
        batch_sizes: vec![1],
        iterations: 10,
        warmup: 2,
        ..Default::default()
    };

    let bench = InferenceBenchmark::new("bench_model", config);

    c.bench_function("inference_latency_batch_1", |b| {
        b.iter(|| {
            let results = bench.run_all();
            black_box(results);
        });
    });
}

fn inference_batch_scaling_bench(c: &mut Criterion) {
    let config = InferenceConfig {
        batch_sizes: vec![1, 8],
        iterations: 5,
        warmup: 1,
        ..Default::default()
    };

    let bench = InferenceBenchmark::new("bench_model", config);

    c.bench_function("inference_batch_scaling", |b| {
        b.iter(|| {
            let results = bench.run_all();
            black_box(results);
        });
    });
}

criterion_group!(
    benches,
    inference_latency_bench,
    inference_batch_scaling_bench
);
criterion_main!(benches);
