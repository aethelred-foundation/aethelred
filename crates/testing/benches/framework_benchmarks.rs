//! Testing framework benchmarks using criterion.
//!
//! These benchmarks measure the overhead and performance of the
//! Aethelred testing framework itself.

use aethelred_testing::TestCase;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn test_case_creation_bench(c: &mut Criterion) {
    c.bench_function("test_case_creation", |b| {
        b.iter(|| {
            let tc = TestCase::new("bench_test", || {});
            black_box(tc);
        });
    });
}

fn test_case_execution_bench(c: &mut Criterion) {
    c.bench_function("test_case_execution_noop", |b| {
        b.iter(|| {
            let tc = TestCase::new("bench_test", || {});
            let result = tc.run();
            black_box(result);
        });
    });
}

criterion_group!(benches, test_case_creation_bench, test_case_execution_bench);
criterion_main!(benches);
