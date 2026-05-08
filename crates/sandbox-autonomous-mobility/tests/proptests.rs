//! Property-based tests for sandbox-autonomous-mobility.

use aethelred_sandbox_autonomous_mobility::*;
use proptest::prelude::*;

fn rta() -> AutonomousMobilitySandbox {
    AutonomousMobilitySandbox::quickstart("RTA").unwrap()
}

proptest! {
    #[test]
    fn many_clean_seals_verify(n in 1usize..=15usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_odd_validation(OddValidation::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn merkle_root_stable(n in 1usize..=10usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_odd_validation(OddValidation::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn audit_size_matches(n in 1usize..=10usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_odd_validation(OddValidation::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }

    #[test]
    fn perception_seal_count(n in 1usize..=10usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_perception_event(PerceptionEvent::demo()).unwrap();
        }
        prop_assert_eq!(sb.seal_count(), n);
    }

    #[test]
    fn mission_step_seal_count(n in 1usize..=10usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_mission_step(MissionStep::demo()).unwrap();
        }
        prop_assert_eq!(sb.seal_count(), n);
    }

    #[test]
    fn safety_event_seal_count(n in 1usize..=10usize) {
        let sb = rta();
        for _ in 0..n {
            sb.seal_safety_case_event(SafetyCaseEvent::demo()).unwrap();
        }
        prop_assert_eq!(sb.seal_count(), n);
    }
}
