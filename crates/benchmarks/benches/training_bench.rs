//! Training benchmarks using criterion.
//!
//! These benchmarks measure the performance of model training operations
//! including forward/backward pass and optimizer steps.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use aethelred_benchmarks::training::{TrainingBenchmark, TrainingConfig};

fn training_forward_bench(c: &mut Criterion) {
    let config = TrainingConfig {
        batch_sizes: vec![1],
        warmup_steps: 2,
        steps: 5,
        ..Default::default()
    };

    let bench = TrainingBenchmark::new("bench_model", config);

    c.bench_function("training_forward_batch_1", |b| {
        b.iter(|| {
            let result = bench.benchmark_forward(1);
            black_box(result);
        });
    });
}

fn training_full_step_bench(c: &mut Criterion) {
    let config = TrainingConfig {
        batch_sizes: vec![1],
        warmup_steps: 1,
        steps: 3,
        ..Default::default()
    };

    let bench = TrainingBenchmark::new("bench_model", config);

    c.bench_function("training_full_step_batch_1", |b| {
        b.iter(|| {
            let result = bench.benchmark_full_step(1);
            black_box(result);
        });
    });
}

criterion_group!(benches, training_forward_bench, training_full_step_bench);
criterion_main!(benches);
