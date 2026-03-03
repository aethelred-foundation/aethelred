use criterion::{criterion_group, criterion_main, Criterion};

fn bench_faucet_drip_rate(c: &mut Criterion) {
    c.bench_function("faucet_drip_single", |b| {
        b.iter(|| {
            // Simulate a single faucet drip: address validation + balance check + transfer.
            let address = "aethel1testaddr000000000000000000000000000";
            let _valid = address.starts_with("aethel1") && address.len() >= 39;
            let _amount: u64 = 1_000_000; // 1 AETHEL in uaethel
        });
    });

    c.bench_function("faucet_rate_limit_check", |b| {
        use std::collections::HashMap;
        let mut ledger: HashMap<&str, u64> = HashMap::new();
        let addr = "aethel1testaddr";
        ledger.insert(addr, 1);

        b.iter(|| {
            let count = ledger.get(addr).copied().unwrap_or(0);
            let _allowed = count < 5; // max 5 drips per window
        });
    });
}

fn bench_faucet_batch(c: &mut Criterion) {
    c.bench_function("faucet_batch_100_drips", |b| {
        let addresses: Vec<String> = (0..100)
            .map(|i| format!("aethel1testaddr{:040}", i))
            .collect();

        b.iter(|| {
            let mut total: u64 = 0;
            for addr in &addresses {
                if addr.starts_with("aethel1") {
                    total += 1_000_000;
                }
            }
            total
        });
    });
}

criterion_group!(benches, bench_faucet_drip_rate, bench_faucet_batch);
criterion_main!(benches);
