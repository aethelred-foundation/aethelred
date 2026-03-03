use criterion::{criterion_group, criterion_main, Criterion};
use falcon_lion::{version_info, DemoConfig, FalconLionDemo};

fn bench_version_info(c: &mut Criterion) {
    c.bench_function("version_info", |b| b.iter(|| version_info()));
}

fn bench_demo_init(c: &mut Criterion) {
    c.bench_function("demo_init", |b| {
        b.iter(|| FalconLionDemo::new(DemoConfig::default()))
    });
}

criterion_group!(benches, bench_version_info, bench_demo_init);
criterion_main!(benches);
