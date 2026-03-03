use criterion::{criterion_group, criterion_main, Criterion};

fn consensus_benchmarks(c: &mut Criterion) {
    c.bench_function("noop", |b| b.iter(|| 1u64.wrapping_add(1)));
}

criterion_group!(benches, consensus_benchmarks);
criterion_main!(benches);
