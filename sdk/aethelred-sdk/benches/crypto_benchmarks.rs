use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};

fn bench_sha256(c: &mut Criterion) {
    let input = vec![0u8; 4096];
    c.bench_function("sha256_4kb", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(&input));
            black_box(hasher.finalize())
        })
    });
}

criterion_group!(benches, bench_sha256);
criterion_main!(benches);
