//! Memory benchmarks using criterion.
//!
//! These benchmarks measure memory allocation performance,
//! bandwidth, and pool efficiency.

use aethelred_benchmarks::memory::{MemoryBenchmark, MemoryBenchmarkConfig};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn memory_allocation_bench(c: &mut Criterion) {
    let config = MemoryBenchmarkConfig {
        allocation_sizes: vec![1024, 1024 * 1024],
        iterations: 10,
        test_fragmentation: false,
        test_bandwidth: false,
    };

    let bench = MemoryBenchmark::new(config);

    c.bench_function("memory_allocation_1kb", |b| {
        b.iter(|| {
            let result = bench.benchmark_allocation(1024);
            black_box(result);
        });
    });
}

fn memory_bandwidth_bench(c: &mut Criterion) {
    let config = MemoryBenchmarkConfig {
        allocation_sizes: vec![1024 * 1024],
        iterations: 5,
        test_bandwidth: true,
        test_fragmentation: false,
    };

    let bench = MemoryBenchmark::new(config);

    c.bench_function("memory_bandwidth_1mb", |b| {
        b.iter(|| {
            let result = bench.benchmark_bandwidth(1024 * 1024);
            black_box(result);
        });
    });
}

criterion_group!(benches, memory_allocation_bench, memory_bandwidth_bench);
criterion_main!(benches);
