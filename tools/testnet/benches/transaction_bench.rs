use criterion::{criterion_group, criterion_main, Criterion};

fn bench_tx_serialization(c: &mut Criterion) {
    c.bench_function("tx_serialize_json", |b| {
        let tx = serde_json::json!({
            "type": "transfer",
            "from": "aethel1sender00000000000000000000000000000",
            "to": "aethel1receiver000000000000000000000000000",
            "amount": {"denom": "uaethel", "amount": "1000000"},
            "memo": "",
            "sequence": 42_u64,
            "chain_id": "aethelred-testnet-1",
        });

        b.iter(|| {
            let _bytes = serde_json::to_vec(&tx).unwrap();
        });
    });

    c.bench_function("tx_deserialize_json", |b| {
        let raw = br#"{"type":"transfer","from":"aethel1sender","to":"aethel1receiver","amount":{"denom":"uaethel","amount":"1000000"},"memo":"","sequence":42,"chain_id":"aethelred-testnet-1"}"#;

        b.iter(|| {
            let _val: serde_json::Value = serde_json::from_slice(raw).unwrap();
        });
    });
}

fn bench_tx_hash(c: &mut Criterion) {
    use sha2::{Digest, Sha256};

    c.bench_function("tx_sha256_hash", |b| {
        let payload = b"transfer|aethel1sender|aethel1receiver|1000000uaethel|42";

        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(payload);
            let _hash = hasher.finalize();
        });
    });

    c.bench_function("tx_batch_hash_1000", |b| {
        let payloads: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("transfer|aethel1sender|aethel1receiver|{}uaethel|{}", i * 1000, i).into_bytes())
            .collect();

        b.iter(|| {
            let mut hashes = Vec::with_capacity(1000);
            for p in &payloads {
                let mut hasher = Sha256::new();
                hasher.update(p);
                hashes.push(hasher.finalize());
            }
            hashes
        });
    });
}

criterion_group!(benches, bench_tx_serialization, bench_tx_hash);
criterion_main!(benches);
