//! Criterion benchmarks for the hot paths.
//!
//! Run: `cargo bench -p aethelred-sandbox-core --features real-crypto`.
//!
//! Reports cover:
//! - SHA-256 over canonical seal JSON (the leaf-hash hot path).
//! - Merkle proof construction on logs of various sizes.
//! - Hybrid (ECDSA + Dilithium-3) sign + verify (where Dilithium dominates).
//! - JSONL persistence append (fsync vs no-sync).
//! - Scanner throughput on a realistic mixed-content document.

use aethelred_sandbox_core::evidence::EvidenceLog;
use aethelred_sandbox_core::hashing::{Hasher, Sha256Digest};
use aethelred_sandbox_core::seal::{
    ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealVersion,
};
use aethelred_sandbox_core::Sector;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[cfg(feature = "real-crypto")]
use aethelred_sandbox_core::crypto_signing::{HybridSealSigner, HybridSealVerifier, SealSigner};

fn seal(seed: u64) -> DigitalSeal {
    DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: "credit_decision".into(),
        event_hash: Hasher::sha256(format!("event-{seed}").as_bytes()),
        model: ModelReference::new("credit_v3", Hasher::sha256(b"weights")),
        policy_id: "po_credit_v1".into(),
        input_hash: Hasher::sha256(format!("in-{seed}").as_bytes()),
        output_hash: Hasher::sha256(format!("out-{seed}").as_bytes()),
        approvals: vec![ApprovalRecord::unsigned("u#1", "underwriter", "approved")],
        attestation: None,
        zk_proof: None,
        tenant_id: "FAB".into(),
        workflow_id: "credit_decision".into(),
        jurisdiction_tag: "AE-CBUAE".into(),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension: BTreeMap::new(),
        validator_signature_hex: None,
    }
}

fn bench_sha256_seal(c: &mut Criterion) {
    let s = seal(0);
    c.bench_function("hash_value/seal", |b| {
        b.iter(|| {
            let h = Hasher::hash_value(black_box(&s)).unwrap();
            black_box(h);
        })
    });
}

fn bench_merkle_proof_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_build");
    for n in [16usize, 64, 256, 1024] {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(seal(i as u64)).unwrap();
        }
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let mid = (n / 2) as u64;
                let p = log.proof(black_box(mid)).unwrap();
                black_box(p);
            })
        });
    }
    group.finish();
}

fn bench_merkle_proof_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verify");
    for n in [16usize, 64, 256, 1024] {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(seal(i as u64)).unwrap();
        }
        let proof = log.proof((n / 2) as u64).unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _n| {
            b.iter(|| {
                let ok = black_box(&proof).verify();
                black_box(ok);
            })
        });
    }
    group.finish();
}

#[cfg(feature = "real-crypto")]
fn bench_hybrid_sign(c: &mut Criterion) {
    let signer = HybridSealSigner::generate("bench-signer").unwrap();
    let s = seal(0);
    c.bench_function("hybrid_sign", |b| {
        b.iter(|| {
            let signed = signer.sign_seal(black_box(s.clone())).unwrap();
            black_box(signed);
        })
    });
}

#[cfg(feature = "real-crypto")]
fn bench_hybrid_verify(c: &mut Criterion) {
    let signer = HybridSealSigner::generate("bench-signer").unwrap();
    let signed = signer.sign_seal(seal(0)).unwrap();
    let verifier = HybridSealVerifier::for_signer("bench-signer", signer.public_key().clone());
    c.bench_function("hybrid_verify", |b| {
        b.iter(|| {
            verifier.verify_signed_seal(black_box(&signed)).unwrap();
        })
    });
}

fn bench_evidence_log_append(c: &mut Criterion) {
    c.bench_function("evidence_log/append_1k", |b| {
        b.iter(|| {
            let log = EvidenceLog::new();
            for i in 0..1000u64 {
                log.append(black_box(seal(i))).unwrap();
            }
            black_box(log.len());
        })
    });
}

fn bench_scanner_mixed_doc(c: &mut Criterion) {
    use aethelred_sandbox_core::scanner::Scanner;
    let s = Scanner::new();
    let doc = "\
This invoice notes user@example.com paid with card 4111 1111 1111 1111 \
on 2026-05-06. SSN on file: 123-45-6789. Patient mrn:1234567 has DOB. \
Classification: SECRET//NOFORN. Token: Xq8rLp2VnA9dKfMb3sZcW7yEhGtJuRiP.";
    c.bench_function("scanner/mixed_doc", |bencher| {
        bencher.iter(|| {
            let f = s.scan(black_box(doc));
            black_box(f.len());
        })
    });
}

fn bench_pre_sig_hash(c: &mut Criterion) {
    let s = seal(0);
    c.bench_function("seal/pre_signature_hash", |b| {
        b.iter(|| {
            let h: Sha256Digest = black_box(&s).pre_signature_hash().unwrap();
            black_box(h);
        })
    });
}

#[cfg(feature = "real-crypto")]
criterion_group!(
    benches,
    bench_sha256_seal,
    bench_pre_sig_hash,
    bench_merkle_proof_build,
    bench_merkle_proof_verify,
    bench_evidence_log_append,
    bench_hybrid_sign,
    bench_hybrid_verify,
    bench_scanner_mixed_doc,
);

#[cfg(not(feature = "real-crypto"))]
criterion_group!(
    benches,
    bench_sha256_seal,
    bench_pre_sig_hash,
    bench_merkle_proof_build,
    bench_merkle_proof_verify,
    bench_evidence_log_append,
    bench_scanner_mixed_doc,
);

criterion_main!(benches);
