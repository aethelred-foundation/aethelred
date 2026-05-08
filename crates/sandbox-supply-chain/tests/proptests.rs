//! Property-based tests for sandbox-supply-chain.

use aethelred_sandbox_supply_chain::*;
use proptest::prelude::*;
use rust_decimal::Decimal;

fn kezad() -> SupplyChainSandbox {
    SupplyChainSandbox::quickstart("KEZAD").unwrap()
}

proptest! {
    #[test]
    fn negative_carbon_always_blocks(amt in 1i64..=1_000_000i64) {
        let sb = SupplyChainSandbox::quickstart("Masdar").unwrap();
        let mut c = CarbonClaim::demo();
        c.emissions_kg_co2e = Decimal::new(-amt, 0);
        prop_assert!(sb.seal_carbon_claim(c).is_err());
    }

    #[test]
    fn negative_methane_always_blocks(amt in 1i64..=1_000_000i64) {
        let sb = SupplyChainSandbox::builder()
            .tenant("ADNOC")
            .jurisdiction(SupplyChainJurisdiction::EuMethane)
            .build()
            .unwrap();
        let mut m = MethaneEvent::demo();
        m.emission_kg_ch4 = Decimal::new(-amt, 0);
        prop_assert!(sb.seal_methane_event(m).is_err());
    }

    #[test]
    fn many_clean_seals_verify(n in 1usize..=15usize) {
        let sb = kezad();
        for _ in 0..n {
            sb.seal_batch_event(BatchEvent::demo()).unwrap();
        }
        let r = sb.verify_all().unwrap();
        prop_assert_eq!(r.len(), n);
        for x in &r {
            prop_assert!(x.passed());
        }
    }

    #[test]
    fn merkle_root_stable(n in 1usize..=10usize) {
        let sb = kezad();
        for _ in 0..n {
            sb.seal_batch_event(BatchEvent::demo()).unwrap();
        }
        let r1 = sb.current_root().unwrap();
        let r2 = sb.current_root().unwrap();
        prop_assert_eq!(r1, r2);
    }

    #[test]
    fn audit_trail_size_matches(n in 1usize..=10usize) {
        let sb = kezad();
        for _ in 0..n {
            sb.seal_batch_event(BatchEvent::demo()).unwrap();
        }
        let trail = sb.audit_trail_struct().unwrap();
        prop_assert_eq!(trail.entries.len(), n);
    }
}
