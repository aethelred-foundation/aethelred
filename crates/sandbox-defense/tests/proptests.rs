//! Property-based tests for sandbox-defense.

use aethelred_sandbox_defense::prelude::*;
use proptest::prelude::*;

fn edge() -> DefenseSandbox {
    DefenseSandbox::quickstart("EDGE").unwrap()
}

proptest! {
    #[test]
    fn outside_odd_always_seals_with_review(seed in any::<u32>()) {
        // ODD is optional; seal emits but policy is ReviewRequired.
        let sb = edge();
        let mut a = AutonomousLogistics::demo();
        a.within_odd = false;
        a.mission_id = format!("m-{seed}");
        prop_assert!(sb.seal_autonomous_logistics(a).is_ok());
    }

    #[test]
    fn classified_marker_always_blocks_check(local in "[a-zA-Z0-9 ]{0,30}") {
        let sb = edge();
        let s = format!("{local} CLASSIFICATION: TS//SCI suffix");
        prop_assert!(sb.check_classification_boundary(&s).is_err());
    }

    #[test]
    fn benign_strings_pass_classification(s in "[a-z0-9 ]{1,40}") {
        // skip strings that happen to contain forbidden tokens
        prop_assume!(!s.to_uppercase().contains("CLASSIFICATION:"));
        prop_assume!(!s.to_uppercase().contains("SECRET//"));
        prop_assume!(!s.to_uppercase().contains("CONFIDENTIAL//"));
        prop_assume!(!s.to_uppercase().contains("TS//SCI"));
        let sb = edge();
        prop_assert!(sb.check_classification_boundary(&s).is_ok());
    }

    #[test]
    fn many_clean_logistics_seals_verify(n in 1usize..=15usize) {
        let sb = edge();
        for _ in 0..n {
            sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn merkle_root_stable(n in 1usize..=10usize) {
        let sb = edge();
        for _ in 0..n {
            sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn audit_size_matches(n in 1usize..=10usize) {
        let sb = edge();
        for _ in 0..n {
            sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }
}
