//! Property-based tests for the sandbox-core invariants.
//!
//! Each `proptest!` block generates 256 random cases by default. We assert
//! the invariants enterprise users rely on:
//!
//! 1. `Hasher::sha256` is deterministic.
//! 2. `Hasher::sha256` is collision-resistant for short inputs (different
//!    bytes ⇒ different digest).
//! 3. `Hasher::merkle_combine` is order-sensitive.
//! 4. `Hasher::merkle_root` over 1..=64 leaves is well-defined and produces
//!    a 32-byte digest.
//! 5. Every leaf in an EvidenceLog has a verifiable Merkle proof.
//! 6. PolicyEngine is fail-closed dominant: if any *required* gate fails,
//!    the decision is `FailClosed` regardless of optional gate state.
//! 7. `DigitalSeal::pre_signature_hash` is invariant under
//!    `validator_signature_hex` mutation.

use aethelred_sandbox_core::evidence::EvidenceLog;
use aethelred_sandbox_core::hashing::{Hasher, Sha256Digest};
use aethelred_sandbox_core::policy::{Decision, PolicyEngine, PolicyGate};
use aethelred_sandbox_core::seal::{
    ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealVersion,
};
use aethelred_sandbox_core::Sector;
use proptest::prelude::*;
use std::collections::{BTreeMap, HashMap};
use time::OffsetDateTime;
use uuid::Uuid;

fn arb_seal(payload_seed: u64) -> DigitalSeal {
    DigitalSeal {
        schema_version: SealVersion::V1,
        seal_id: Uuid::now_v7(),
        timestamp: OffsetDateTime::now_utc(),
        sector: Sector::Finance,
        event_type: "credit_decision".into(),
        event_hash: Hasher::sha256(format!("event-{}", payload_seed).as_bytes()),
        model: ModelReference::new("model", Hasher::sha256(b"weights")),
        policy_id: "po".into(),
        input_hash: Hasher::sha256(format!("in-{}", payload_seed).as_bytes()),
        output_hash: Hasher::sha256(format!("out-{}", payload_seed).as_bytes()),
        approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
        attestation: None,
        zk_proof: None,
        tenant_id: "TENANT".into(),
        workflow_id: "wf".into(),
        jurisdiction_tag: "AE".into(),
        retention: RetentionClass::SevenYears,
        prior_seal_hash: None,
        sector_extension: BTreeMap::new(),
        validator_signature_hex: None,
    }
}

proptest! {
    // --- Hashing ---

    #[test]
    fn sha256_is_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let h1 = Hasher::sha256(&bytes);
        let h2 = Hasher::sha256(&bytes);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_diff_inputs_diff_hash(
        a in proptest::collection::vec(any::<u8>(), 1..256),
        b in proptest::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(Hasher::sha256(&a), Hasher::sha256(&b));
    }

    #[test]
    fn merkle_combine_order_sensitive(
        a in proptest::collection::vec(any::<u8>(), 1..64),
        b in proptest::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(a != b);
        let ha = Hasher::sha256(&a);
        let hb = Hasher::sha256(&b);
        let lr = Hasher::merkle_combine(ha, hb);
        let rl = Hasher::merkle_combine(hb, ha);
        prop_assert_ne!(lr, rl);
    }

    #[test]
    fn merkle_root_is_32_bytes(n in 1usize..64) {
        let leaves: Vec<Sha256Digest> = (0..n)
            .map(|i| Hasher::sha256(format!("leaf-{i}").as_bytes()))
            .collect();
        let root = Hasher::merkle_root(&leaves);
        prop_assert_eq!(root.0.len(), 32);
    }

    #[test]
    fn merkle_root_singleton_is_leaf(seed in any::<u64>()) {
        let leaf = Hasher::sha256(format!("leaf-{seed}").as_bytes());
        let root = Hasher::merkle_root(&[leaf]);
        prop_assert_eq!(leaf, root);
    }

    // --- Evidence log + proofs ---

    #[test]
    fn every_evidence_proof_verifies(n in 1usize..32) {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(arb_seal(i as u64)).unwrap();
        }
        let root = log.root().unwrap();
        for i in 0..n {
            let proof = log.proof(i as u64).unwrap();
            prop_assert!(proof.verify());
            prop_assert_eq!(proof.root, root);
        }
    }

    #[test]
    fn evidence_root_changes_when_seal_added(n in 1usize..16) {
        let log = EvidenceLog::new();
        for i in 0..n {
            log.append(arb_seal(i as u64)).unwrap();
        }
        let r_before = log.root().unwrap();
        log.append(arb_seal(9999)).unwrap();
        let r_after = log.root().unwrap();
        prop_assert_ne!(r_before, r_after);
    }

    #[test]
    fn evidence_indices_are_monotonic(n in 1usize..16) {
        let log = EvidenceLog::new();
        let mut last = None;
        for i in 0..n {
            let entry = log.append(arb_seal(i as u64)).unwrap();
            if let Some(prev) = last {
                prop_assert!(entry.index > prev);
            }
            last = Some(entry.index);
        }
    }

    // --- Policy engine fail-closed dominance ---

    #[test]
    fn required_failure_dominates(
        opt_a in any::<bool>(),
        opt_b in any::<bool>(),
        req_a in any::<bool>(),
        req_b in any::<bool>(),
    ) {
        let engine = PolicyEngine::new(vec![
            PolicyGate::required("test.required_a", "Req A", "rule"),
            PolicyGate::required("test.required_b", "Req B", "rule"),
            PolicyGate::optional("test.optional_a", "Opt A", "rule"),
            PolicyGate::optional("test.optional_b", "Opt B", "rule"),
        ]);
        let mut faults = HashMap::new();
        faults.insert("test.required_a".into(), req_a);
        faults.insert("test.required_b".into(), req_b);
        faults.insert("test.optional_a".into(), opt_a);
        faults.insert("test.optional_b".into(), opt_b);
        let (decision, _) = engine.evaluate(&faults);
        let any_required_failed = req_a || req_b;
        if any_required_failed {
            prop_assert_eq!(decision, Decision::FailClosed);
        } else if opt_a || opt_b {
            prop_assert_eq!(decision, Decision::ReviewRequired);
        } else {
            prop_assert_eq!(decision, Decision::Allow);
        }
    }

    // --- Seal pre-signature determinism ---

    #[test]
    fn pre_signature_hash_excludes_validator_signature(
        sig_byte in any::<u8>(),
        seed in any::<u64>(),
    ) {
        let mut s = arb_seal(seed);
        let h_unsigned = s.pre_signature_hash().unwrap();
        s.validator_signature_hex = Some(format!("{:02x}{:02x}", sig_byte, sig_byte));
        let h_signed = s.pre_signature_hash().unwrap();
        prop_assert_eq!(h_unsigned, h_signed);
    }

    #[test]
    fn seal_serde_roundtrip(seed in any::<u64>()) {
        let s = arb_seal(seed);
        let j = serde_json::to_string(&s).unwrap();
        let p: DigitalSeal = serde_json::from_str(&j).unwrap();
        prop_assert_eq!(p.event_hash, s.event_hash);
        prop_assert_eq!(p.policy_id, s.policy_id);
    }

    #[test]
    fn changing_event_hash_changes_pre_signature_hash(seed_a in any::<u64>(), seed_b in any::<u64>()) {
        prop_assume!(seed_a != seed_b);
        let mut a = arb_seal(seed_a);
        let mut b = arb_seal(seed_b);
        // Equalize all other random fields so only event_hash differs.
        b.seal_id = a.seal_id;
        b.timestamp = a.timestamp;
        a.event_hash = Hasher::sha256(format!("ea-{seed_a}").as_bytes());
        b.event_hash = Hasher::sha256(format!("eb-{seed_b}").as_bytes());
        // Equalize other content-fields to isolate event_hash.
        b.input_hash = a.input_hash;
        b.output_hash = a.output_hash;
        let ha = a.pre_signature_hash().unwrap();
        let hb = b.pre_signature_hash().unwrap();
        prop_assert_ne!(ha, hb);
    }
}
