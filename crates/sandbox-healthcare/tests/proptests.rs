//! Property-based tests for sandbox-healthcare.

use aethelred_sandbox_healthcare::prelude::*;
use proptest::prelude::*;

fn m42() -> HealthcareSandbox {
    HealthcareSandbox::quickstart("M42").unwrap()
}

proptest! {
    #[test]
    fn email_in_genomics_pseudo_always_blocks(local in "[a-z]{2,8}", domain in "[a-z]{3,10}") {
        let sb = m42();
        let mut g = GenomicsInference::demo();
        g.sample_pseudo_id = format!("{local}@{domain}.com");
        prop_assert!(sb.seal_genomics_inference(g).is_err());
    }

    #[test]
    fn mrn_marker_always_blocks_clinical(seed in any::<u32>()) {
        let sb = m42();
        let mut c = ClinicalInference::demo();
        c.encounter_pseudo_id = format!("mrn:{seed}");
        prop_assert!(sb.seal_clinical_inference(c).is_err());
    }

    #[test]
    fn ssn_marker_always_blocks_claims(seed in any::<u32>()) {
        let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
        let mut c = ClaimsAdjudication::demo();
        c.member_pseudo_id = format!("ssn:{seed:09}");
        prop_assert!(sb.seal_claims_adjudication(c).is_err());
    }

    #[test]
    fn unsigned_ambient_always_blocks(seed in any::<u32>()) {
        let sb = m42();
        let mut a = AmbientNote::demo();
        a.clinician_signed = false;
        a.encounter_pseudo_id = format!("psn:{seed}");
        prop_assert!(sb.seal_ambient_note(a).is_err());
    }

    #[test]
    fn many_clean_genomics_seals_verify(n in 1usize..=15usize) {
        let sb = m42();
        for _ in 0..n {
            sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn many_clean_clinical_seals_verify(n in 1usize..=15usize) {
        let sb = m42();
        for _ in 0..n {
            sb.seal_clinical_inference(ClinicalInference::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn audit_trail_size_matches_seal_count(n in 1usize..=10usize) {
        let sb = m42();
        for _ in 0..n {
            sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }

    #[test]
    fn merkle_root_stable_across_reads(n in 1usize..=10usize) {
        let sb = m42();
        for _ in 0..n {
            sb.seal_genomics_inference(GenomicsInference::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }
}
