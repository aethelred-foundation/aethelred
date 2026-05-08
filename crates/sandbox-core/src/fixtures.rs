//! Fixture catalog — named, realistic scenarios every sector crate publishes.
//!
//! Enterprise users hate boilerplate. They want to write:
//!
//! ```ignore
//! use aethelred_sandbox_finance::prelude::*;
//!
//! let sb = FinanceSandbox::quickstart("FAB")?;
//! for fix in FinanceFixtures::happy_path() {
//!     sb.run_fixture(&fix)?;
//! }
//! ```
//!
//! ...and have a working AML / credit / trading pilot in 4 lines. This module
//! defines the `Fixture` trait that every sector implements, plus a
//! `FixtureCatalog` that groups them by intent (happy-path, adversarial,
//! regulatory-edge).
//!
//! ## Why not just `Vec<EventInput>`?
//!
//! Three reasons:
//!
//! 1. **Naming** — reviewers want `fab.aml.high_risk_jurisdiction` in the
//!    audit trail, not `seal_42`.
//! 2. **Tags** — fixtures carry sector-specific tags so SOCs can filter
//!    (`#cbuae`, `#fatf-rec-11`, `#human-override-required`).
//! 3. **Expected outcome** — every fixture declares whether it should `Allow`,
//!    `ReviewRequired`, or `FailClosed`. Sector adversarial test suites use
//!    this to drive parameterized assertions in one line.

use crate::policy::Decision;
use serde::{Deserialize, Serialize};

/// One named realistic scenario.
///
/// Sector crates publish concrete `Fixture` impls. Enterprise users iterate
/// them via [`FixtureCatalog`].
pub trait Fixture: Send + Sync + std::fmt::Debug {
    /// Stable, sector-prefixed id (e.g., `"finance.aml.happy_path"`).
    fn id(&self) -> &str;
    /// Human-readable name.
    fn name(&self) -> &str;
    /// One-sentence description for documentation.
    fn description(&self) -> &str;
    /// Free-form tags (e.g., `["cbuae", "fatf-rec-11", "happy"]`).
    fn tags(&self) -> Vec<&str>;
    /// Expected sandbox decision when the fixture runs against a fresh
    /// production-default sandbox.
    fn expected_decision(&self) -> Decision;
    /// Sector this fixture belongs to.
    fn sector(&self) -> crate::Sector;
}

/// Lightweight, serializable summary of a fixture for catalogue export.
///
/// Sector crates use this to emit fixture catalogues into customer
/// onboarding portals without exposing the underlying Rust trait objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSummary {
    /// Stable id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// One-line description.
    pub description: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Expected decision.
    pub expected_decision: Decision,
    /// Sector.
    pub sector: crate::Sector,
}

impl FixtureSummary {
    /// Construct a summary from any concrete `Fixture`.
    pub fn from_fixture(f: &dyn Fixture) -> Self {
        Self {
            id: f.id().to_string(),
            name: f.name().to_string(),
            description: f.description().to_string(),
            tags: f.tags().into_iter().map(|s| s.to_string()).collect(),
            expected_decision: f.expected_decision(),
            sector: f.sector(),
        }
    }
}

/// A catalog of fixtures grouped by intent.
///
/// Sector crates expose three top-level catalogs:
///
/// - `happy_path()` — pilot demo, expected `Allow`.
/// - `regulatory_edge()` — boundary cases, expected `ReviewRequired` or `Allow`.
/// - `adversarial()` — attacks / fraud, expected `FailClosed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCatalog {
    /// Catalog identifier (e.g., `"finance"`).
    pub catalog_id: String,
    /// Catalog display name.
    pub name: String,
    /// All fixtures.
    pub fixtures: Vec<FixtureSummary>,
}

impl FixtureCatalog {
    /// Construct an empty catalog.
    pub fn new(catalog_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            catalog_id: catalog_id.into(),
            name: name.into(),
            fixtures: Vec::new(),
        }
    }

    /// Add a fixture summary.
    pub fn push(&mut self, summary: FixtureSummary) -> &mut Self {
        self.fixtures.push(summary);
        self
    }

    /// Add many fixture summaries.
    pub fn extend(&mut self, summaries: impl IntoIterator<Item = FixtureSummary>) -> &mut Self {
        self.fixtures.extend(summaries);
        self
    }

    /// Total fixtures.
    pub fn total(&self) -> usize {
        self.fixtures.len()
    }

    /// All fixtures with the given tag.
    pub fn by_tag(&self, tag: &str) -> Vec<&FixtureSummary> {
        self.fixtures
            .iter()
            .filter(|f| f.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// All fixtures with the given expected decision.
    pub fn by_decision(&self, decision: Decision) -> Vec<&FixtureSummary> {
        self.fixtures
            .iter()
            .filter(|f| f.expected_decision == decision)
            .collect()
    }

    /// All happy-path fixtures (expected `Allow`).
    pub fn happy_path(&self) -> Vec<&FixtureSummary> {
        self.by_decision(Decision::Allow)
    }

    /// All adversarial fixtures (expected `FailClosed`).
    pub fn adversarial(&self) -> Vec<&FixtureSummary> {
        self.by_decision(Decision::FailClosed)
    }

    /// All regulatory-edge fixtures (expected `ReviewRequired`).
    pub fn regulatory_edge(&self) -> Vec<&FixtureSummary> {
        self.by_decision(Decision::ReviewRequired)
    }

    /// Look up a fixture summary by id.
    pub fn find(&self, id: &str) -> Option<&FixtureSummary> {
        self.fixtures.iter().find(|f| f.id == id)
    }

    /// All distinct tags in the catalog.
    pub fn distinct_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .fixtures
            .iter()
            .flat_map(|f| f.tags.iter().cloned())
            .collect();
        tags.sort();
        tags.dedup();
        tags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestFixture {
        id: &'static str,
        decision: Decision,
        tags: Vec<&'static str>,
    }

    impl Fixture for TestFixture {
        fn id(&self) -> &str {
            self.id
        }
        fn name(&self) -> &str {
            "Test fixture"
        }
        fn description(&self) -> &str {
            "test"
        }
        fn tags(&self) -> Vec<&str> {
            self.tags.clone()
        }
        fn expected_decision(&self) -> Decision {
            self.decision
        }
        fn sector(&self) -> crate::Sector {
            crate::Sector::Finance
        }
    }

    fn fab_catalog() -> FixtureCatalog {
        let happy = TestFixture {
            id: "finance.happy",
            decision: Decision::Allow,
            tags: vec!["happy", "cbuae"],
        };
        let edge = TestFixture {
            id: "finance.edge",
            decision: Decision::ReviewRequired,
            tags: vec!["edge", "cbuae"],
        };
        let adv = TestFixture {
            id: "finance.adversarial",
            decision: Decision::FailClosed,
            tags: vec!["adversarial", "fraud"],
        };
        let mut cat = FixtureCatalog::new("finance", "Finance Fixtures");
        cat.push(FixtureSummary::from_fixture(&happy));
        cat.push(FixtureSummary::from_fixture(&edge));
        cat.push(FixtureSummary::from_fixture(&adv));
        cat
    }

    #[test]
    fn empty_catalog_has_no_fixtures() {
        let cat = FixtureCatalog::new("x", "X");
        assert_eq!(cat.total(), 0);
    }

    #[test]
    fn catalog_groups_by_decision() {
        let cat = fab_catalog();
        assert_eq!(cat.happy_path().len(), 1);
        assert_eq!(cat.regulatory_edge().len(), 1);
        assert_eq!(cat.adversarial().len(), 1);
    }

    #[test]
    fn catalog_finds_by_id() {
        let cat = fab_catalog();
        assert!(cat.find("finance.happy").is_some());
        assert!(cat.find("nope").is_none());
    }

    #[test]
    fn catalog_filters_by_tag() {
        let cat = fab_catalog();
        let cb = cat.by_tag("cbuae");
        assert_eq!(cb.len(), 2);
        let fraud = cat.by_tag("fraud");
        assert_eq!(fraud.len(), 1);
    }

    #[test]
    fn distinct_tags_are_sorted_and_deduped() {
        let cat = fab_catalog();
        let tags = cat.distinct_tags();
        let mut expected = tags.clone();
        expected.sort();
        expected.dedup();
        assert_eq!(tags, expected);
    }

    #[test]
    fn catalog_serde_roundtrip() {
        let cat = fab_catalog();
        let j = serde_json::to_string(&cat).unwrap();
        let p: FixtureCatalog = serde_json::from_str(&j).unwrap();
        assert_eq!(p.total(), cat.total());
        assert_eq!(p.catalog_id, cat.catalog_id);
    }

    #[test]
    fn extend_adds_multiple() {
        let mut cat = FixtureCatalog::new("x", "X");
        let a = TestFixture { id: "a", decision: Decision::Allow, tags: vec![] };
        let b = TestFixture { id: "b", decision: Decision::Allow, tags: vec![] };
        cat.extend([
            FixtureSummary::from_fixture(&a),
            FixtureSummary::from_fixture(&b),
        ]);
        assert_eq!(cat.total(), 2);
    }

    #[test]
    fn push_returns_mut_self_for_chaining() {
        let mut cat = FixtureCatalog::new("x", "X");
        let a = TestFixture { id: "a", decision: Decision::Allow, tags: vec![] };
        cat.push(FixtureSummary::from_fixture(&a));
        assert_eq!(cat.total(), 1);
    }
}
