//! Property-based tests for sandbox-research.

use aethelred_sandbox_research::*;
use proptest::prelude::*;

fn mbz() -> ResearchSandbox {
    ResearchSandbox::quickstart("MBZUAI").unwrap()
}

proptest! {
    #[test]
    fn many_experiments_verify(n in 1usize..=15usize) {
        let sb = mbz();
        for _ in 0..n {
            sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn many_releases_verify(n in 1usize..=10usize) {
        let sb = mbz();
        for _ in 0..n {
            sb.seal_model_release(ModelReleasePack::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn merkle_root_stable(n in 1usize..=10usize) {
        let sb = mbz();
        for _ in 0..n {
            sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn audit_size_matches(n in 1usize..=10usize) {
        let sb = mbz();
        for _ in 0..n {
            sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }

    #[test]
    fn experiment_seal_count(n in 1usize..=10usize) {
        let sb = mbz();
        for _ in 0..n {
            sb.seal_experiment_run(ExperimentRun::demo()).unwrap();
        }
        prop_assert_eq!(sb.seal_count(), n);
    }
}
