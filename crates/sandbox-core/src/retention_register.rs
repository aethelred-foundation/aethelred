//! Data-retention class registry.
//!
//! Maps to GDPR Art 5(1)(e) (storage limitation), HIPAA §164.530(j),
//! SOX §802 (financial 7-year retention), CCPA §1798.105, and ISO 27001
//! A.8.3.2. Every category of data the controller processes must have a
//! documented retention class: how long it is kept, the legal basis for
//! that period, the disposition method, and any legal-hold override
//! exceptions.
//!
//! Distinct from [`crate::retention_purge`] (which **executes** the
//! deletions) and [`crate::seal`]'s `RetentionClass` enum (which tags
//! individual seals), this is the **policy catalog** that maps free-form
//! data categories to retention rules.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// LegalBasis
// =============================================================================

/// Why we keep the data this long.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionBasis {
    /// Statute (e.g., SOX 7y, HIPAA 6y).
    Statutory,
    /// Contract with customer.
    Contractual,
    /// Legitimate business interest (must be documented).
    BusinessInterest,
    /// Subject consent.
    Consent,
    /// Litigation hold or regulatory investigation.
    LegalHold,
}

// =============================================================================
// Disposition
// =============================================================================

/// How data is disposed when retention ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Hard delete from primary + backups.
    HardDelete,
    /// Cryptographic shred (delete the encryption key).
    CryptoShred,
    /// Anonymise (hash / generalise) so subject identity cannot be recovered.
    Anonymise,
    /// Aggregate (collapse to statistical summary).
    Aggregate,
    /// Archive to cold storage with restricted access.
    ArchiveColdStorage,
}

// =============================================================================
// RetentionClass
// =============================================================================

/// One retention class — the policy applied to a category of data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetentionClass {
    /// Stable id (e.g., "transaction-records", "customer-pii", "logs-30d").
    pub class_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Long-form description of what is covered.
    pub description: String,
    /// Maximum retention in days. 0 = indefinite (must have legal hold or
    /// statutory basis).
    pub max_age_days: u64,
    /// Legal basis.
    pub basis: RetentionBasis,
    /// Optional citation (e.g., "SOX §802", "HIPAA 45 CFR 164.530(j)").
    pub citation: Option<String>,
    /// Disposition at end of life.
    pub disposition: Disposition,
    /// Owner.
    pub owner: String,
    /// Whether the class is currently active. Inactive classes remain in
    /// the registry for audit but no new data is mapped to them.
    pub active: bool,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// RFC 3339 — registered.
    pub created_at: String,
    /// RFC 3339 — last reviewed (annual review is best-practice).
    pub last_reviewed_at: Option<String>,
}

impl RetentionClass {
    /// Construct a new active class.
    pub fn new(
        class_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        max_age_days: u64,
        basis: RetentionBasis,
        disposition: Disposition,
        owner: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            class_id: class_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            description: description.into(),
            max_age_days,
            basis,
            citation: None,
            disposition,
            owner: owner.into(),
            active: true,
            tags: Vec::new(),
            created_at: created_at.into(),
            last_reviewed_at: None,
        }
    }

    /// True if this class permits indefinite retention.
    pub fn is_indefinite(&self) -> bool {
        self.max_age_days == 0
    }

    /// True if `now - created_at` exceeds `max_age_days`.
    pub fn would_expire(&self, ingested_at: &str, now: &str) -> bool {
        if self.is_indefinite() {
            return false;
        }
        match age_in_days(ingested_at, now) {
            Some(d) => d >= self.max_age_days as i64,
            None => false,
        }
    }

    /// True if a class is missing the annual review (more than 365 days
    /// since `last_reviewed_at` or `created_at`).
    pub fn review_overdue(&self, now: &str) -> bool {
        let anchor = self
            .last_reviewed_at
            .as_deref()
            .unwrap_or(&self.created_at);
        match age_in_days(anchor, now) {
            Some(d) => d >= 365,
            None => false,
        }
    }
}

// =============================================================================
// CategoryAssignment
// =============================================================================

/// Map a free-form data category onto a retention class.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategoryAssignment {
    /// Tenant scope.
    pub tenant_id: String,
    /// Free-form category identifier.
    pub category: String,
    /// Retention class applied.
    pub class_id: String,
    /// Optional note.
    pub note: Option<String>,
}

// =============================================================================
// RetentionRegister
// =============================================================================

/// Thread-safe registry of retention classes plus category assignments.
#[derive(Debug, Default)]
pub struct RetentionRegister {
    classes: RwLock<HashMap<String, RetentionClass>>,
    assignments: RwLock<HashMap<(String, String), CategoryAssignment>>, // (tenant, category)
}

impl RetentionRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new retention class.
    pub fn register_class(&self, class: RetentionClass) -> SandboxResult<()> {
        let mut g = self
            .classes
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        if g.contains_key(&class.class_id) {
            return Err(SandboxError::Other(format!(
                "retention class already registered: {}",
                class.class_id
            )));
        }
        g.insert(class.class_id.clone(), class);
        Ok(())
    }

    /// Set citation on a class.
    pub fn set_citation(
        &self,
        class_id: &str,
        citation: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .classes
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        let c = g
            .get_mut(class_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown class {class_id}")))?;
        c.citation = Some(citation.into());
        Ok(())
    }

    /// Mark a class as reviewed at `at`.
    pub fn mark_reviewed(&self, class_id: &str, at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .classes
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        let c = g
            .get_mut(class_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown class {class_id}")))?;
        c.last_reviewed_at = Some(at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, class_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .classes
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        let c = g
            .get_mut(class_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown class {class_id}")))?;
        let tag = tag.into();
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Mark a class active / inactive.
    pub fn set_active(&self, class_id: &str, active: bool) -> SandboxResult<()> {
        let mut g = self
            .classes
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        let c = g
            .get_mut(class_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown class {class_id}")))?;
        c.active = active;
        Ok(())
    }

    /// Look up a class.
    pub fn get_class(&self, class_id: &str) -> Option<RetentionClass> {
        let g = self.classes.read().ok()?;
        g.get(class_id).cloned()
    }

    /// All classes.
    pub fn all_classes(&self) -> Vec<RetentionClass> {
        match self.classes.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Active classes.
    pub fn active_classes(&self) -> Vec<RetentionClass> {
        self.all_classes().into_iter().filter(|c| c.active).collect()
    }

    /// Classes whose annual review is overdue at `now`.
    pub fn classes_review_overdue(&self, now: &str) -> Vec<RetentionClass> {
        self.all_classes()
            .into_iter()
            .filter(|c| c.review_overdue(now))
            .collect()
    }

    /// Classes for a tenant.
    pub fn classes_for_tenant(&self, tenant_id: &str) -> Vec<RetentionClass> {
        self.all_classes()
            .into_iter()
            .filter(|c| c.tenant_id == tenant_id)
            .collect()
    }

    /// Assign a free-form data category to a retention class. Errors if the
    /// referenced class is unknown or not in the same tenant.
    pub fn assign_category(
        &self,
        assignment: CategoryAssignment,
    ) -> SandboxResult<()> {
        let class_tenant = {
            let g = self
                .classes
                .read()
                .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
            let c = g.get(&assignment.class_id).ok_or_else(|| {
                SandboxError::Other(format!("unknown class {}", assignment.class_id))
            })?;
            c.tenant_id.clone()
        };
        if class_tenant != assignment.tenant_id {
            return Err(SandboxError::Other(format!(
                "tenant mismatch: assignment {}, class {}",
                assignment.tenant_id, class_tenant
            )));
        }
        let mut g = self
            .assignments
            .write()
            .map_err(|_| SandboxError::Other("retention register poisoned".into()))?;
        g.insert(
            (assignment.tenant_id.clone(), assignment.category.clone()),
            assignment,
        );
        Ok(())
    }

    /// Remove a category assignment. Returns the prior assignment, if any.
    pub fn unassign_category(
        &self,
        tenant_id: &str,
        category: &str,
    ) -> Option<CategoryAssignment> {
        let mut g = self.assignments.write().ok()?;
        g.remove(&(tenant_id.to_string(), category.to_string()))
    }

    /// Look up the retention class for a category, if assigned.
    pub fn class_for_category(
        &self,
        tenant_id: &str,
        category: &str,
    ) -> Option<RetentionClass> {
        let g = self.assignments.read().ok()?;
        let assignment =
            g.get(&(tenant_id.to_string(), category.to_string()))?.clone();
        drop(g);
        self.get_class(&assignment.class_id)
    }

    /// All assignments for a tenant.
    pub fn assignments_for_tenant(&self, tenant_id: &str) -> Vec<CategoryAssignment> {
        match self.assignments.read() {
            Ok(g) => g
                .values()
                .filter(|a| a.tenant_id == tenant_id)
                .cloned()
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Categories that have no retention class assigned. Caller supplies
    /// the universe of categories they expect to be governed.
    pub fn unassigned_categories(
        &self,
        tenant_id: &str,
        expected: &[String],
    ) -> Vec<String> {
        let g = match self.assignments.read() {
            Ok(g) => g,
            Err(_) => return expected.to_vec(),
        };
        expected
            .iter()
            .filter(|c| !g.contains_key(&(tenant_id.to_string(), (*c).clone())))
            .cloned()
            .collect()
    }

    /// Class count.
    pub fn class_count(&self) -> usize {
        self.classes.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Assignment count.
    pub fn assignment_count(&self) -> usize {
        self.assignments.read().map(|g| g.len()).unwrap_or(0)
    }
}

fn age_in_days(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn class(id: &str, days: u64) -> RetentionClass {
        RetentionClass::new(
            id,
            "tenant-a",
            format!("name-{id}"),
            "desc",
            days,
            RetentionBasis::Statutory,
            Disposition::HardDelete,
            "data-team",
            "2025-01-01T00:00:00Z",
        )
    }

    fn assignment(class_id: &str, category: &str) -> CategoryAssignment {
        CategoryAssignment {
            tenant_id: "tenant-a".into(),
            category: category.into(),
            class_id: class_id.into(),
            note: None,
        }
    }

    #[test]
    fn register_and_get_class() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        let g = r.get_class("c1").unwrap();
        assert_eq!(g.max_age_days, 30);
        assert!(g.active);
    }

    #[test]
    fn duplicate_class_errors() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        let err = r.register_class(class("c1", 90)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn set_citation_set_active_set_review() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.set_citation("c1", "SOX §802").unwrap();
        r.mark_reviewed("c1", "2025-04-01T00:00:00Z").unwrap();
        r.set_active("c1", false).unwrap();
        let c = r.get_class("c1").unwrap();
        assert_eq!(c.citation.as_deref(), Some("SOX §802"));
        assert_eq!(c.last_reviewed_at.as_deref(), Some("2025-04-01T00:00:00Z"));
        assert!(!c.active);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.add_tag("c1", "pii").unwrap();
        r.add_tag("c1", "pii").unwrap();
        r.add_tag("c1", "regulated").unwrap();
        assert_eq!(r.get_class("c1").unwrap().tags, vec!["pii", "regulated"]);
    }

    #[test]
    fn unknown_class_errors() {
        let r = RetentionRegister::new();
        let err = r.set_citation("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown class"));
    }

    #[test]
    fn is_indefinite_zero_days() {
        assert!(class("c", 0).is_indefinite());
        assert!(!class("c", 30).is_indefinite());
    }

    #[test]
    fn would_expire_uses_ingested_at() {
        let c = class("c", 30);
        assert!(c.would_expire("2025-01-01T00:00:00Z", "2025-02-15T00:00:00Z"));
        assert!(!c.would_expire("2025-01-01T00:00:00Z", "2025-01-15T00:00:00Z"));
    }

    #[test]
    fn would_expire_indefinite_never_expires() {
        let c = class("c", 0);
        assert!(!c.would_expire("2025-01-01T00:00:00Z", "2030-01-01T00:00:00Z"));
    }

    #[test]
    fn review_overdue_yearly_anchor() {
        let c = class("c", 30); // created 2025-01-01
        // 2026-01-02 is 366 days later → overdue
        assert!(c.review_overdue("2026-01-02T00:00:00Z"));
        assert!(!c.review_overdue("2025-12-15T00:00:00Z"));
    }

    #[test]
    fn review_overdue_uses_last_reviewed_when_present() {
        let r = RetentionRegister::new();
        r.register_class(class("c", 30)).unwrap();
        r.mark_reviewed("c", "2025-12-01T00:00:00Z").unwrap();
        let c = r.get_class("c").unwrap();
        assert!(!c.review_overdue("2026-06-01T00:00:00Z"));
        assert!(c.review_overdue("2026-12-15T00:00:00Z"));
    }

    #[test]
    fn classes_review_overdue_query() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.register_class(class("c2", 30)).unwrap();
        r.mark_reviewed("c2", "2025-12-01T00:00:00Z").unwrap();
        let due = r.classes_review_overdue("2026-06-01T00:00:00Z");
        let ids: Vec<_> = due.iter().map(|c| c.class_id.clone()).collect();
        assert!(ids.contains(&"c1".to_string())); // never reviewed; 1 year+ old
        assert!(!ids.contains(&"c2".to_string())); // reviewed 6 months ago
    }

    #[test]
    fn classes_for_tenant_filters() {
        let r = RetentionRegister::new();
        r.register_class(class("a", 30)).unwrap();
        let mut other = class("b", 30);
        other.tenant_id = "tenant-b".into();
        r.register_class(other).unwrap();
        assert_eq!(r.classes_for_tenant("tenant-a").len(), 1);
        assert_eq!(r.classes_for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn active_classes_filters() {
        let r = RetentionRegister::new();
        r.register_class(class("a", 30)).unwrap();
        r.register_class(class("b", 30)).unwrap();
        r.set_active("a", false).unwrap();
        let active = r.active_classes();
        let ids: Vec<_> = active.iter().map(|c| c.class_id.clone()).collect();
        assert_eq!(ids, vec!["b"]);
    }

    #[test]
    fn assign_category_resolves() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.assign_category(assignment("c1", "logs")).unwrap();
        let resolved = r.class_for_category("tenant-a", "logs").unwrap();
        assert_eq!(resolved.class_id, "c1");
    }

    #[test]
    fn assign_unknown_class_errors() {
        let r = RetentionRegister::new();
        let err = r
            .assign_category(assignment("missing", "logs"))
            .unwrap_err();
        assert!(format!("{err}").contains("unknown class"));
    }

    #[test]
    fn assign_tenant_mismatch_errors() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        let mut a = assignment("c1", "logs");
        a.tenant_id = "tenant-b".into();
        let err = r.assign_category(a).unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn assign_overwrites() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.register_class(class("c2", 60)).unwrap();
        r.assign_category(assignment("c1", "logs")).unwrap();
        r.assign_category(assignment("c2", "logs")).unwrap();
        let resolved = r.class_for_category("tenant-a", "logs").unwrap();
        assert_eq!(resolved.class_id, "c2");
    }

    #[test]
    fn unassign_works() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.assign_category(assignment("c1", "logs")).unwrap();
        assert!(r.unassign_category("tenant-a", "logs").is_some());
        assert!(r.class_for_category("tenant-a", "logs").is_none());
    }

    #[test]
    fn assignments_for_tenant_filters() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.assign_category(assignment("c1", "logs")).unwrap();
        r.assign_category(assignment("c1", "metrics")).unwrap();
        assert_eq!(r.assignments_for_tenant("tenant-a").len(), 2);
        assert_eq!(r.assignments_for_tenant("tenant-b").len(), 0);
    }

    #[test]
    fn unassigned_categories() {
        let r = RetentionRegister::new();
        r.register_class(class("c1", 30)).unwrap();
        r.assign_category(assignment("c1", "logs")).unwrap();
        let expected = vec!["logs".to_string(), "metrics".to_string(), "events".to_string()];
        let missing = r.unassigned_categories("tenant-a", &expected);
        assert!(missing.contains(&"metrics".to_string()));
        assert!(missing.contains(&"events".to_string()));
        assert!(!missing.contains(&"logs".to_string()));
    }

    #[test]
    fn class_count_and_assignment_count() {
        let r = RetentionRegister::new();
        assert_eq!(r.class_count(), 0);
        r.register_class(class("c1", 30)).unwrap();
        assert_eq!(r.class_count(), 1);
        r.assign_category(assignment("c1", "logs")).unwrap();
        assert_eq!(r.assignment_count(), 1);
    }

    #[test]
    fn class_serde() {
        let c = class("c", 30);
        let j = serde_json::to_string(&c).unwrap();
        let back: RetentionClass = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn assignment_serde() {
        let a = assignment("c", "logs");
        let j = serde_json::to_string(&a).unwrap();
        let back: CategoryAssignment = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enums_serde() {
        for b in [
            RetentionBasis::Statutory,
            RetentionBasis::Contractual,
            RetentionBasis::BusinessInterest,
            RetentionBasis::Consent,
            RetentionBasis::LegalHold,
        ] {
            assert_eq!(
                b,
                serde_json::from_str::<RetentionBasis>(&serde_json::to_string(&b).unwrap()).unwrap()
            );
        }
        for d in [
            Disposition::HardDelete,
            Disposition::CryptoShred,
            Disposition::Anonymise,
            Disposition::Aggregate,
            Disposition::ArchiveColdStorage,
        ] {
            assert_eq!(
                d,
                serde_json::from_str::<Disposition>(&serde_json::to_string(&d).unwrap()).unwrap()
            );
        }
    }
}
