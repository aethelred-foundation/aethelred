//! Property-based tests for sandbox-ai-agents.

use aethelred_sandbox_ai_agents::*;
use proptest::prelude::*;

fn lab() -> AiAgentsSandbox {
    AiAgentsSandbox::quickstart("AI-Lab").unwrap()
}

proptest! {
    #[test]
    fn unrejected_pi_test_always_blocks(seed in any::<u32>()) {
        let sb = lab();
        let mut p = PromptInjectionTest::demo();
        p.rejected = false;
        p.test_id = format!("t-{seed}");
        prop_assert!(sb.seal_prompt_injection_test(p).is_err());
    }

    #[test]
    fn rejected_pi_test_always_seals(seed in any::<u32>()) {
        let sb = lab();
        let mut p = PromptInjectionTest::demo();
        p.rejected = true;
        p.test_id = format!("t-{seed}");
        prop_assert!(sb.seal_prompt_injection_test(p).is_ok());
    }

    #[test]
    fn many_clean_passports_verify(n in 1usize..=15usize) {
        let sb = lab();
        for _ in 0..n {
            sb.seal_passport(AgentPassport::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn merkle_root_stable(n in 1usize..=10usize) {
        let sb = lab();
        for _ in 0..n {
            sb.seal_passport(AgentPassport::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn audit_size_matches(n in 1usize..=10usize) {
        let sb = lab();
        for _ in 0..n {
            sb.seal_passport(AgentPassport::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }

    #[test]
    fn passport_seal_count_grows(n in 1usize..=10usize) {
        let sb = lab();
        for _ in 0..n {
            sb.seal_passport(AgentPassport::demo()).unwrap();
        }
        prop_assert_eq!(sb.seal_count(), n);
    }
}
