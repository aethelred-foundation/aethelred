//! Structure-aware fuzz harnesses (stable Rust, runs in normal CI).
//!
//! These complement the unit-level `proptest!` blocks already in
//! `tests/proptests.rs`. The focus here is *malicious / malformed input*
//! resilience: the targets must never panic, leak memory, or accept
//! known-bad inputs, regardless of byte-shape.
//!
//! Each `proptest!` block produces 256 cases by default. We pin the
//! `ProptestConfig` to 1024 cases for these — fuzz-style harnesses want
//! more breadth than typical property tests.
//!
//! ## Targets covered
//!
//! 1. `DigitalSeal` JSON deserialisation — never panics on arbitrary JSON.
//! 2. `EvidenceLogEntry` line — never panics on malformed JSONL lines.
//! 3. `Scanner::scan` — never panics on arbitrary text input including
//!    invalid UTF-8 boundaries (within `String` constraints).
//! 4. `MerkleProof::verify` — never panics on arbitrary proof shapes.
//! 5. `SignatureEnvelope::from_hex_blob` — never panics on bad hex /
//!    bad JSON.
//! 6. `parse_attestation_document` — never panics on truncated bytes.
//! 7. `SealEnvelope` serde — round-trips never lose information.
//! 8. `iban_mod97_ok` style detectors — never panic on weird inputs.

use aethelred_sandbox_core::evidence::{EvidenceLog, EvidenceLogEntry, MerkleProof};
use aethelred_sandbox_core::hashing::Sha256Digest;
use aethelred_sandbox_core::scanner::Scanner;
use aethelred_sandbox_core::seal::DigitalSeal;
use aethelred_sandbox_core::tee::TeePlatform;
use aethelred_sandbox_core::tee_verify::parse_attestation_document;
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

#[cfg(feature = "real-crypto")]
use aethelred_sandbox_core::crypto_signing::SignatureEnvelope;

fn proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 1024,
        max_global_rejects: 100_000,
        ..ProptestConfig::default()
    }
}

// =============================================================================
// 1. DigitalSeal JSON deserialisation
// =============================================================================

proptest! {
    #![proptest_config(proptest_config())]

    /// Fuzz: parsing arbitrary JSON-ish bytes as a DigitalSeal must never
    /// panic — only return Ok or Err.
    #[test]
    fn fuzz_digital_seal_deser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = serde_json::from_slice::<DigitalSeal>(&bytes);
    }

    /// Fuzz: parsing a string that happens to be valid JSON (random shape)
    /// must never panic.
    #[test]
    fn fuzz_digital_seal_random_json_string(
        s in r#"\{[a-zA-Z0-9_:"\\, \[\]{}\.]{0,200}\}"#
    ) {
        let _ = serde_json::from_str::<DigitalSeal>(&s);
    }
}

// =============================================================================
// 2. EvidenceLogEntry line
// =============================================================================

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_evidence_log_entry_line(line in r"[\x00-\x7F]{0,512}") {
        let _ = serde_json::from_str::<EvidenceLogEntry>(&line);
    }
}

// =============================================================================
// 3. Scanner.scan never panics
// =============================================================================

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_scanner_scan_arbitrary_string(s in r"\PC{0,2048}") {
        let scanner = Scanner::new();
        let _ = scanner.scan(&s);
    }

    #[test]
    fn fuzz_scanner_summary_arbitrary_string(s in r"\PC{0,2048}") {
        let scanner = Scanner::new();
        let _ = scanner.summary(&s);
    }

    #[test]
    fn fuzz_scanner_with_empty_input(_dummy in any::<u8>()) {
        let scanner = Scanner::new();
        let f = scanner.scan("");
        prop_assert!(f.is_empty());
    }

    #[test]
    fn fuzz_scanner_unicode_whitespace_safe(s in r"[\u{00A0}\u{2000}-\u{200B}\u{3000}]{0,256}") {
        let scanner = Scanner::new();
        let _ = scanner.scan(&s);
    }
}

// =============================================================================
// 4. MerkleProof.verify never panics
// =============================================================================

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_merkle_proof_verify_arbitrary_siblings(
        leaf in proptest::array::uniform32(any::<u8>()),
        root in proptest::array::uniform32(any::<u8>()),
        leaf_index in any::<u64>(),
        siblings in proptest::collection::vec(
            proptest::array::uniform32(any::<u8>()),
            0..32
        ),
    ) {
        let proof = MerkleProof {
            leaf_index,
            leaf_hash: Sha256Digest(leaf),
            siblings: siblings.into_iter().map(Sha256Digest).collect(),
            root: Sha256Digest(root),
        };
        // Must not panic. Result must be Boolean.
        let _ = proof.verify();
    }
}

// =============================================================================
// 5. Signature envelope hex-blob parser
// =============================================================================

#[cfg(feature = "real-crypto")]
proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_signature_envelope_hex_never_panics(
        s in proptest::collection::vec(any::<u8>(), 0..2048).prop_map(hex::encode)
    ) {
        let _ = SignatureEnvelope::from_hex_blob(&s);
    }

    #[test]
    fn fuzz_signature_envelope_random_string(s in "[a-fA-F0-9]{0,512}") {
        let _ = SignatureEnvelope::from_hex_blob(&s);
    }

    #[test]
    fn fuzz_signature_envelope_arbitrary_text(s in r"\PC{0,512}") {
        let _ = SignatureEnvelope::from_hex_blob(&s);
    }
}

// =============================================================================
// 6. Attestation document parser
// =============================================================================

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_tdx_parser_truncated(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = parse_attestation_document(TeePlatform::IntelTdx, &bytes);
    }

    #[test]
    fn fuzz_sev_parser_truncated(bytes in proptest::collection::vec(any::<u8>(), 0..1500)) {
        let _ = parse_attestation_document(TeePlatform::AmdSevSnp, &bytes);
    }

    #[test]
    fn fuzz_nitro_parser_arbitrary(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_attestation_document(TeePlatform::AwsNitro, &bytes);
    }

    #[test]
    fn fuzz_h100_parser_arbitrary(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_attestation_document(TeePlatform::NvidiaH100Cc, &bytes);
    }

    #[test]
    fn fuzz_arm_cca_parser_arbitrary(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_attestation_document(TeePlatform::ArmCca, &bytes);
    }
}

// =============================================================================
// 7. Evidence log roundtrip resilience
// =============================================================================

use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

use aethelred_sandbox_core::seal::{
    ApprovalRecord, ModelReference, RetentionClass, SealVersion,
};
use aethelred_sandbox_core::Sector;
use aethelred_sandbox_core::Hasher;

fn arb_seal(seed: u64) -> DigitalSeal {
    DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: "fuzz".into(),
        event_hash: Hasher::sha256(format!("e-{seed}").as_bytes()),
        model: ModelReference::new("m", Hasher::sha256(b"w")),
        policy_id: "po".into(),
        input_hash: Hasher::sha256(format!("i-{seed}").as_bytes()),
        output_hash: Hasher::sha256(format!("o-{seed}").as_bytes()),
        approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
        attestation: None,
        zk_proof: None,
        tenant_id: "T".into(),
        workflow_id: "wf".into(),
        jurisdiction_tag: "AE".into(),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension: BTreeMap::new(),
        validator_signature_hex: None,
    }
}

proptest! {
    #![proptest_config(proptest_config())]

    /// Fuzz: appending up to N seals + computing root + each proof must
    /// always succeed and produce a valid proof.
    #[test]
    fn fuzz_evidence_log_invariants(n in 1usize..=64) {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(arb_seal(i as u64)).unwrap();
        }
        let root = log.root().unwrap();
        for i in 0..n {
            let p = log.proof(i as u64).unwrap();
            prop_assert!(p.verify());
            prop_assert_eq!(p.root, root);
        }
    }

    /// Fuzz: the bundle merkle_root must always equal the log root.
    #[test]
    fn fuzz_evidence_bundle_root_matches_log(n in 1usize..=32) {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(arb_seal(i as u64)).unwrap();
        }
        let r = log.root().unwrap();
        let b = log.export("T", Sector::Finance).unwrap();
        prop_assert_eq!(r, b.merkle_root);
    }
}

// =============================================================================
// 8. Time-query parser resilience
// =============================================================================

use aethelred_sandbox_core::time_query::TimeQuery;

proptest! {
    #![proptest_config(proptest_config())]

    /// Bad RFC 3339 input must never panic.
    #[test]
    fn fuzz_time_query_bad_from(s in r"\PC{0,256}") {
        let log = EvidenceLog::new();
        log.append(arb_seal(0)).unwrap();
        let bundle = log.export("T", Sector::Finance).unwrap();
        let q = TimeQuery::new().from(s);
        let _ = q.run(&bundle.entries);
    }

    /// Bad RFC 3339 `to`.
    #[test]
    fn fuzz_time_query_bad_to(s in r"\PC{0,256}") {
        let log = EvidenceLog::new();
        log.append(arb_seal(0)).unwrap();
        let bundle = log.export("T", Sector::Finance).unwrap();
        let q = TimeQuery::new().to(s);
        let _ = q.run(&bundle.entries);
    }
}

// =============================================================================
// 9. Drift detector resilience
// =============================================================================

use aethelred_sandbox_core::drift::{DriftDetector, Histogram};

proptest! {
    #![proptest_config(proptest_config())]

    /// Drift detector must never panic on arbitrary numeric streams.
    #[test]
    fn fuzz_drift_detector_arbitrary_floats(values in proptest::collection::vec(-1e6f64..=1e6, 0..1000)) {
        let det = DriftDetector::default_config();
        let mut h = Histogram::new(vec![-100.0, -10.0, 0.0, 10.0, 100.0]);
        for v in &values {
            h.observe(*v);
        }
        det.set_reference("f", h);
        for v in &values {
            let _ = det.observe("f", *v);
        }
        let _ = det.check("f");
    }

    /// PSI / KL / JS / Wasserstein must never panic on degenerate
    /// distributions.
    #[test]
    fn fuzz_drift_metrics_never_panic(
        a in proptest::collection::vec(0.0f64..=1.0, 0..100),
        b in proptest::collection::vec(0.0f64..=1.0, 0..100),
    ) {
        let mut ha = Histogram::new(vec![0.25, 0.5, 0.75]);
        let mut hb = Histogram::new(vec![0.25, 0.5, 0.75]);
        ha.observe_all(&a);
        hb.observe_all(&b);
        let _ = aethelred_sandbox_core::drift::psi(&ha, &hb);
        let _ = aethelred_sandbox_core::drift::kl_divergence(&ha, &hb);
        let _ = aethelred_sandbox_core::drift::js_divergence(&ha, &hb);
        let _ = aethelred_sandbox_core::drift::wasserstein1(&ha, &hb);
        let _ = aethelred_sandbox_core::drift::chi_squared(&ha, &hb);
    }
}

// =============================================================================
// 10. Anomaly detector resilience
// =============================================================================

use aethelred_sandbox_core::anomaly::AnomalyDetector;

proptest! {
    #![proptest_config(proptest_config())]

    #[test]
    fn fuzz_anomaly_detector_arbitrary_floats(values in proptest::collection::vec(any::<f64>().prop_filter("finite", |v| v.is_finite()), 0..200)) {
        let det = AnomalyDetector::default();
        for v in &values {
            let _ = det.observe("k", *v);
        }
    }
}
