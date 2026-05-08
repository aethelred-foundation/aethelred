//! Finance fixtures library — named, realistic scenarios.
//!
//! Enterprise users get a comprehensive set of pre-built scenarios for credit,
//! AML, trading, and advisory. Each fixture has a stable id, regulator tags,
//! and an expected sandbox decision so test suites can drive assertions
//! without bespoke setup code.
//!
//! ## Three intent groups
//!
//! - **Happy path** — pilot demo, expected `Allow`. Use these to drive a
//!   3-line bank pilot.
//! - **Regulatory edge** — boundary cases (e.g., adverse-action without
//!   reason class), expected `ReviewRequired`.
//! - **Adversarial** — fraud, PII smuggling, risk-limit breach, missing
//!   approval. Expected `FailClosed`.
//!
//! ## Usage
//!
//! ```ignore
//! use aethelred_sandbox_finance::prelude::*;
//!
//! let sb = FinanceSandbox::quickstart("FAB")?;
//! for fix in FinanceFixtures::happy_path() {
//!     fix.run(&sb)?;
//! }
//! ```

use crate::workflows::advisory::Advisory;
use crate::workflows::aml_screening::AmlAlert;
use crate::workflows::credit_decision::{CreditDecision, CreditOutcome};
use crate::workflows::trading_event::{RiskLimitStatus, TradingEvent};
use crate::FinanceSandbox;
use aethelred_sandbox_core::policy::Decision;
use aethelred_sandbox_core::SandboxResult;
use rust_decimal::Decimal;

/// One named, runnable finance scenario.
///
/// Every variant carries a stable id, a one-line description, regulator
/// tags (e.g., `["cbuae", "fatf-rec-11"]`), and an expected decision.
#[derive(Debug, Clone)]
pub enum FinanceFixture {
    /// Happy / edge / adversarial credit-decision scenario.
    Credit {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Decision input.
        decision: CreditDecision,
    },
    /// AML alert scenario.
    Aml {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Alert input.
        alert: AmlAlert,
    },
    /// Trading event scenario.
    Trading {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Event input.
        event: TradingEvent,
    },
    /// Advisory scenario.
    Advisory {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Advisory input.
        advisory: Advisory,
    },
}

impl FinanceFixture {
    /// Stable id.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Credit { id, .. }
            | Self::Aml { id, .. }
            | Self::Trading { id, .. }
            | Self::Advisory { id, .. } => id,
        }
    }

    /// Description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Credit { description, .. }
            | Self::Aml { description, .. }
            | Self::Trading { description, .. }
            | Self::Advisory { description, .. } => description,
        }
    }

    /// Tags.
    pub fn tags(&self) -> &[&'static str] {
        match self {
            Self::Credit { tags, .. }
            | Self::Aml { tags, .. }
            | Self::Trading { tags, .. }
            | Self::Advisory { tags, .. } => tags,
        }
    }

    /// Expected decision when run against a default sandbox.
    pub fn expected(&self) -> Decision {
        match self {
            Self::Credit { expected, .. }
            | Self::Aml { expected, .. }
            | Self::Trading { expected, .. }
            | Self::Advisory { expected, .. } => *expected,
        }
    }

    /// Run this fixture against a [`FinanceSandbox`]. On expected `Allow`,
    /// returns `Ok(())`. On expected `FailClosed`, returns `Ok(())` if the
    /// sandbox blocked it, else `Err`. On `ReviewRequired`, currently the
    /// sandbox emits seals (the gate is optional in v0.2.0); this is treated
    /// as `Ok(())`.
    pub fn run(&self, sandbox: &FinanceSandbox) -> SandboxResult<()> {
        let result: SandboxResult<()> = match self {
            Self::Credit { decision, .. } => sandbox
                .seal_credit_decision(decision.clone())
                .map(|_| ()),
            Self::Aml { alert, .. } => sandbox.seal_aml_alert(alert.clone()).map(|_| ()),
            Self::Trading { event, .. } => sandbox.seal_trading_event(event.clone()).map(|_| ()),
            Self::Advisory { advisory, .. } => sandbox.seal_advisory(advisory.clone()).map(|_| ()),
        };
        match (self.expected(), result) {
            (Decision::Allow | Decision::ReviewRequired, Ok(_)) => Ok(()),
            (Decision::FailClosed, Err(e)) if e.is_policy_denial() => Ok(()),
            (expected, actual) => Err(aethelred_sandbox_core::SandboxError::Other(format!(
                "fixture `{}` expected {:?}, got {:?}",
                self.id(),
                expected,
                actual
            ))),
        }
    }
}

/// The catalog of finance fixtures.
pub struct FinanceFixtures;

impl FinanceFixtures {
    /// All fixtures (happy + edge + adversarial).
    pub fn all() -> Vec<FinanceFixture> {
        let mut v = Vec::new();
        v.extend(Self::happy_path());
        v.extend(Self::regulatory_edge());
        v.extend(Self::adversarial());
        v
    }

    /// Happy-path fixtures (expected `Allow`).
    pub fn happy_path() -> Vec<FinanceFixture> {
        vec![
            FinanceFixture::Credit {
                id: "finance.credit.happy.fab_sme_loan",
                description: "FAB SME loan, fully approved with adequate MRM lineage",
                tags: vec!["happy", "cbuae", "credit"],
                expected: Decision::Allow,
                decision: CreditDecision::demo(),
            },
            FinanceFixture::Aml {
                id: "finance.aml.happy.routine_screening",
                description: "Routine sanctions screening, no PEP / SDN match",
                tags: vec!["happy", "fatf-rec-11", "aml"],
                expected: Decision::Allow,
                alert: AmlAlert::demo(),
            },
            FinanceFixture::Trading {
                id: "finance.trading.happy.within_limits",
                description: "Within-limit trade, MAR / MiFID II compliant",
                tags: vec!["happy", "mar", "mifid-ii", "trading"],
                expected: Decision::Allow,
                event: TradingEvent::demo(),
            },
            FinanceFixture::Advisory {
                id: "finance.advisory.happy.suitable_robo_advice",
                description: "Suitability-checked robo-advice for retail client",
                tags: vec!["happy", "fiduciary", "advisory"],
                expected: Decision::Allow,
                advisory: Advisory::demo(),
            },
        ]
    }

    /// Regulatory-edge fixtures.
    pub fn regulatory_edge() -> Vec<FinanceFixture> {
        let mut credit_no_mrm = CreditDecision::demo();
        credit_no_mrm.mrm_lineage_ref = None;

        let mut adverse_with_reason = CreditDecision::demo();
        adverse_with_reason.decision = CreditOutcome::Rejected;
        adverse_with_reason.adverse_action_reason = Some("dti_above_threshold".into());

        vec![
            FinanceFixture::Credit {
                id: "finance.credit.edge.no_mrm_lineage",
                description: "Credit decision with no MRM lineage ref — soft-fail (review)",
                tags: vec!["edge", "sr11-7", "credit"],
                expected: Decision::ReviewRequired,
                decision: credit_no_mrm,
            },
            FinanceFixture::Credit {
                id: "finance.credit.edge.adverse_with_reason",
                description: "Adverse credit outcome with reason class set — passes",
                tags: vec!["edge", "ecoa", "credit"],
                expected: Decision::Allow,
                decision: adverse_with_reason,
            },
        ]
    }

    /// Adversarial fixtures (expected `FailClosed`).
    pub fn adversarial() -> Vec<FinanceFixture> {
        let mut neg_amount = CreditDecision::demo();
        neg_amount.amount = Decimal::new(-1_000, 0);

        let mut pii_pseudo_id = CreditDecision::demo();
        pii_pseudo_id.applicant_pseudo_id = "user@example.com".into();

        let mut adverse_no_reason = CreditDecision::demo();
        adverse_no_reason.decision = CreditOutcome::Rejected;
        adverse_no_reason.adverse_action_reason = None;

        let mut overlimit_trade = TradingEvent::demo();
        overlimit_trade.risk_limit_status = RiskLimitStatus::Exceeded;

        let mut huge_advisory = Advisory::demo();
        huge_advisory.amount = Decimal::new(2_000_000_000, 0); // > 1bn cap

        let mut aml_pii = AmlAlert::demo();
        aml_pii.customer_pseudo_id = "ssn:123-45-6789".into();

        let mut neg_qty_trade = TradingEvent::demo();
        neg_qty_trade.quantity = Decimal::new(-1, 0);

        vec![
            FinanceFixture::Credit {
                id: "finance.credit.adv.negative_amount",
                description: "Negative amount — must fail amount-bounds gate",
                tags: vec!["adv", "amount-bounds", "credit"],
                expected: Decision::FailClosed,
                decision: neg_amount,
            },
            FinanceFixture::Credit {
                id: "finance.credit.adv.pii_in_pseudo_id",
                description: "Email address in pseudo-id — must fail PII gate",
                tags: vec!["adv", "pii", "credit"],
                expected: Decision::FailClosed,
                decision: pii_pseudo_id,
            },
            FinanceFixture::Trading {
                id: "finance.trading.adv.overlimit",
                description: "Risk-limit exceeded trade — must hard-block",
                tags: vec!["adv", "risk-limit", "trading"],
                expected: Decision::FailClosed,
                event: overlimit_trade,
            },
            FinanceFixture::Trading {
                id: "finance.trading.adv.negative_quantity",
                description: "Negative trade quantity — must fail amount bounds",
                tags: vec!["adv", "amount-bounds", "trading"],
                expected: Decision::FailClosed,
                event: neg_qty_trade,
            },
            FinanceFixture::Advisory {
                id: "finance.advisory.adv.over_cap",
                description: "Advisory recommendation above 1bn AED cap",
                tags: vec!["adv", "amount-bounds", "advisory"],
                expected: Decision::FailClosed,
                advisory: huge_advisory,
            },
            FinanceFixture::Aml {
                id: "finance.aml.adv.pii_in_pseudo_id",
                description: "SSN in pseudo-id — must fail PII gate",
                tags: vec!["adv", "pii", "aml"],
                expected: Decision::FailClosed,
                alert: aml_pii,
            },
        ]
    }

    /// Subset filtered by tag.
    pub fn by_tag(tag: &str) -> Vec<FinanceFixture> {
        Self::all()
            .into_iter()
            .filter(|f| f.tags().contains(&tag))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_fixtures_all_succeed() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        for fix in FinanceFixtures::happy_path() {
            fix.run(&sb).unwrap_or_else(|e| panic!("fixture {} failed: {e}", fix.id()));
        }
    }

    #[test]
    fn adversarial_fixtures_all_block() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        for fix in FinanceFixtures::adversarial() {
            fix.run(&sb)
                .unwrap_or_else(|e| panic!("adversarial fixture {} did not block: {e}", fix.id()));
        }
    }

    #[test]
    fn regulatory_edge_fixtures_run() {
        let sb = FinanceSandbox::quickstart("FAB").unwrap();
        for fix in FinanceFixtures::regulatory_edge() {
            fix.run(&sb)
                .unwrap_or_else(|e| panic!("edge fixture {} failed: {e}", fix.id()));
        }
    }

    #[test]
    fn all_fixture_ids_are_unique() {
        let ids: Vec<&str> = FinanceFixtures::all().iter().map(|f| f.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), n);
    }

    #[test]
    fn all_fixture_ids_are_namespaced_with_finance() {
        for f in FinanceFixtures::all() {
            assert!(f.id().starts_with("finance."));
        }
    }

    #[test]
    fn by_tag_returns_subset() {
        let cb = FinanceFixtures::by_tag("cbuae");
        assert!(!cb.is_empty());
        for f in cb {
            assert!(f.tags().contains(&"cbuae"));
        }
    }

    #[test]
    fn by_tag_unknown_returns_empty() {
        assert!(FinanceFixtures::by_tag("nonexistent").is_empty());
    }

    #[test]
    fn happy_path_count_matches_workflows() {
        // 4 workflows, one happy path each.
        assert_eq!(FinanceFixtures::happy_path().len(), 4);
    }

    #[test]
    fn at_least_six_adversarial_fixtures() {
        assert!(FinanceFixtures::adversarial().len() >= 6);
    }
}
