//! Model Risk Register — SR 11-7 / OCC 2011-12 model inventory.
//!
//! Federal Reserve SR 11-7 ("Guidance on Model Risk Management") requires
//! every regulated entity to maintain a *model inventory* with a defined
//! validation tier for each model. This module is that inventory.
//!
//! ## Data captured per model
//!
//! - Identification (id, owner, business unit).
//! - Risk **tier** (1=critical → 4=informational).
//! - Validation status (Validated / In Validation / Limitations / Not Approved).
//! - Last validated date and validator.
//! - Decision-impact category (Customer-facing / Internal / Reporting).
//! - Linked policy + workflow ids.
//! - Findings tracker (open issues, severity).
//! - Annual-review schedule.
//!
//! Operators query the register for things like "show every Tier-1 model
//! whose last validation is older than 12 months." That's the report a
//! Fed examiner asks for.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// RiskTier
// =============================================================================

/// Per-model risk tier (SR 11-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Tier 1 — critical (high $-impact, regulated).
    Tier1,
    /// Tier 2 — important.
    Tier2,
    /// Tier 3 — supporting.
    Tier3,
    /// Tier 4 — informational only.
    Tier4,
}

impl RiskTier {
    /// Required revalidation interval in days.
    pub fn revalidation_interval_days(self) -> i64 {
        match self {
            Self::Tier1 => 365,
            Self::Tier2 => 365 * 2,
            Self::Tier3 => 365 * 3,
            Self::Tier4 => 365 * 5,
        }
    }
}

// =============================================================================
// ValidationStatus
// =============================================================================

/// Validation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Model is fully validated.
    Validated,
    /// Validation is in progress.
    InValidation,
    /// Approved with documented limitations.
    LimitationsApproved,
    /// Not approved for production use.
    NotApproved,
    /// Newly registered, not yet reviewed.
    Pending,
}

// =============================================================================
// DecisionImpact
// =============================================================================

/// Where the model's output goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionImpact {
    /// Drives customer-facing decisions (loan approve, claim approve).
    CustomerFacing,
    /// Internal operational use.
    InternalOperational,
    /// Regulatory / financial reporting input.
    RegulatoryReporting,
    /// Research / R&D only.
    Research,
}

// =============================================================================
// Finding
// =============================================================================

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
    /// Informational.
    Info,
}

/// One open / closed finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Stable id.
    pub finding_id: Uuid,
    /// Severity.
    pub severity: FindingSeverity,
    /// Finding text.
    pub text: String,
    /// `true` if open.
    pub is_open: bool,
    /// RFC 3339 raised-at.
    pub raised_at: String,
    /// RFC 3339 closed-at.
    pub closed_at: Option<String>,
}

impl Finding {
    /// New open finding now.
    pub fn open(severity: FindingSeverity, text: impl Into<String>) -> Self {
        Self {
            finding_id: Uuid::now_v7(),
            severity,
            text: text.into(),
            is_open: true,
            raised_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            closed_at: None,
        }
    }
}

// =============================================================================
// ModelEntry
// =============================================================================

/// One registered model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelEntry {
    /// Stable id.
    pub model_id: String,
    /// Display name.
    pub name: String,
    /// Owner / responsible team.
    pub owner: String,
    /// Tier.
    pub tier: RiskTier,
    /// Validation status.
    pub status: ValidationStatus,
    /// Decision impact.
    pub decision_impact: DecisionImpact,
    /// RFC 3339 last validated date.
    pub last_validated_at: Option<String>,
    /// Validator name.
    pub last_validated_by: Option<String>,
    /// Linked policy ids.
    pub policy_ids: Vec<String>,
    /// Linked workflow ids.
    pub workflow_ids: Vec<String>,
    /// Open + closed findings.
    pub findings: Vec<Finding>,
    /// Free-text description.
    pub description: String,
    /// RFC 3339 first-registered.
    pub registered_at: String,
}

impl ModelEntry {
    /// Open findings only.
    pub fn open_findings(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.is_open).collect()
    }
    /// Highest-severity open finding (most severe wins).
    pub fn highest_open_severity(&self) -> Option<FindingSeverity> {
        self.findings
            .iter()
            .filter(|f| f.is_open)
            .map(|f| f.severity)
            .min_by_key(|s| severity_rank(*s))
    }
    /// `true` if the model is overdue for revalidation as of `now`.
    pub fn is_overdue(&self, now: OffsetDateTime) -> bool {
        let last = match &self.last_validated_at {
            Some(s) => match OffsetDateTime::parse(
                s,
                &time::format_description::well_known::Rfc3339,
            ) {
                Ok(t) => t,
                Err(_) => return true,
            },
            None => return true,
        };
        let interval = time::Duration::days(self.tier.revalidation_interval_days());
        now > last + interval
    }
}

fn severity_rank(s: FindingSeverity) -> u8 {
    match s {
        FindingSeverity::Critical => 0,
        FindingSeverity::High => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::Low => 3,
        FindingSeverity::Info => 4,
    }
}

// =============================================================================
// ModelRiskRegister
// =============================================================================

#[derive(Default)]
struct State {
    entries: HashMap<String, ModelEntry>,
}

/// Registry of model entries.
pub struct ModelRiskRegister {
    state: RwLock<State>,
}

impl Default for ModelRiskRegister {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ModelRiskRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelRiskRegister")
            .field("entries", &self.len())
            .finish()
    }
}

impl ModelRiskRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a model.
    pub fn register(
        &self,
        model_id: impl Into<String>,
        name: impl Into<String>,
        owner: impl Into<String>,
        tier: RiskTier,
        impact: DecisionImpact,
    ) -> SandboxResult<ModelEntry> {
        let model_id = model_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        if g.entries.contains_key(&model_id) {
            return Err(SandboxError::Other(format!(
                "model {} already registered",
                model_id
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let entry = ModelEntry {
            model_id: model_id.clone(),
            name: name.into(),
            owner: owner.into(),
            tier,
            status: ValidationStatus::Pending,
            decision_impact: impact,
            last_validated_at: None,
            last_validated_by: None,
            policy_ids: Vec::new(),
            workflow_ids: Vec::new(),
            findings: Vec::new(),
            description: String::new(),
            registered_at: now,
        };
        g.entries.insert(model_id, entry.clone());
        Ok(entry)
    }

    /// Update validation result.
    pub fn record_validation(
        &self,
        model_id: &str,
        status: ValidationStatus,
        validator: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        let e = g
            .entries
            .get_mut(model_id)
            .ok_or_else(|| SandboxError::Other(format!("model {} not found", model_id)))?;
        e.status = status;
        e.last_validated_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        e.last_validated_by = Some(validator.into());
        Ok(())
    }

    /// Add a finding.
    pub fn add_finding(&self, model_id: &str, finding: Finding) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        let e = g
            .entries
            .get_mut(model_id)
            .ok_or_else(|| SandboxError::Other(format!("model {} not found", model_id)))?;
        e.findings.push(finding);
        Ok(())
    }

    /// Close a finding.
    pub fn close_finding(&self, model_id: &str, finding_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        let e = g
            .entries
            .get_mut(model_id)
            .ok_or_else(|| SandboxError::Other(format!("model {} not found", model_id)))?;
        let f = e
            .findings
            .iter_mut()
            .find(|f| f.finding_id == finding_id)
            .ok_or_else(|| {
                SandboxError::Other(format!(
                    "finding {} not in model {}",
                    finding_id, model_id
                ))
            })?;
        f.is_open = false;
        f.closed_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        Ok(())
    }

    /// Link a policy.
    pub fn link_policy(&self, model_id: &str, policy_id: impl Into<String>) -> SandboxResult<()> {
        let policy_id = policy_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        let e = g
            .entries
            .get_mut(model_id)
            .ok_or_else(|| SandboxError::Other(format!("model {} not found", model_id)))?;
        if !e.policy_ids.contains(&policy_id) {
            e.policy_ids.push(policy_id);
        }
        Ok(())
    }

    /// Link a workflow.
    pub fn link_workflow(
        &self,
        model_id: &str,
        workflow_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let wf = workflow_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("model register poisoned".into()))?;
        let e = g
            .entries
            .get_mut(model_id)
            .ok_or_else(|| SandboxError::Other(format!("model {} not found", model_id)))?;
        if !e.workflow_ids.contains(&wf) {
            e.workflow_ids.push(wf);
        }
        Ok(())
    }

    /// Snapshot one entry.
    pub fn lookup(&self, model_id: &str) -> Option<ModelEntry> {
        self.state.read().ok()?.entries.get(model_id).cloned()
    }

    /// All entries.
    pub fn all(&self) -> Vec<ModelEntry> {
        self.state
            .read()
            .map(|g| g.entries.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Filter by tier.
    pub fn by_tier(&self, tier: RiskTier) -> Vec<ModelEntry> {
        self.all().into_iter().filter(|e| e.tier == tier).collect()
    }

    /// Filter by status.
    pub fn by_status(&self, status: ValidationStatus) -> Vec<ModelEntry> {
        self.all().into_iter().filter(|e| e.status == status).collect()
    }

    /// Models overdue for revalidation as of `now`.
    pub fn overdue(&self, now: OffsetDateTime) -> Vec<ModelEntry> {
        self.all().into_iter().filter(|e| e.is_overdue(now)).collect()
    }

    /// Entry count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.entries.len()).unwrap_or(0)
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> ModelRiskRegister {
        let r = ModelRiskRegister::new();
        r.register(
            "m1",
            "Credit Risk v3",
            "ml-platform",
            RiskTier::Tier1,
            DecisionImpact::CustomerFacing,
        )
        .unwrap();
        r
    }

    #[test]
    fn register_creates_entry() {
        let r = reg();
        assert_eq!(r.len(), 1);
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.tier, RiskTier::Tier1);
        assert_eq!(e.status, ValidationStatus::Pending);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = reg();
        assert!(r
            .register(
                "m1",
                "x",
                "y",
                RiskTier::Tier3,
                DecisionImpact::Research,
            )
            .is_err());
    }

    #[test]
    fn record_validation_updates() {
        let r = reg();
        r.record_validation("m1", ValidationStatus::Validated, "v1")
            .unwrap();
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.status, ValidationStatus::Validated);
        assert!(e.last_validated_at.is_some());
        assert_eq!(e.last_validated_by.as_deref(), Some("v1"));
    }

    #[test]
    fn record_validation_unknown_errors() {
        let r = reg();
        assert!(r
            .record_validation("ghost", ValidationStatus::Validated, "v")
            .is_err());
    }

    #[test]
    fn add_finding_records_it() {
        let r = reg();
        r.add_finding("m1", Finding::open(FindingSeverity::High, "drift"))
            .unwrap();
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.findings.len(), 1);
        assert!(e.findings[0].is_open);
    }

    #[test]
    fn close_finding_marks_closed() {
        let r = reg();
        let f = Finding::open(FindingSeverity::High, "drift");
        let id = f.finding_id;
        r.add_finding("m1", f).unwrap();
        r.close_finding("m1", id).unwrap();
        let e = r.lookup("m1").unwrap();
        assert!(!e.findings[0].is_open);
        assert!(e.findings[0].closed_at.is_some());
    }

    #[test]
    fn close_unknown_finding_errors() {
        let r = reg();
        assert!(r.close_finding("m1", Uuid::now_v7()).is_err());
    }

    #[test]
    fn link_policy_dedupes() {
        let r = reg();
        r.link_policy("m1", "p1").unwrap();
        r.link_policy("m1", "p1").unwrap();
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.policy_ids, vec!["p1"]);
    }

    #[test]
    fn link_workflow_works() {
        let r = reg();
        r.link_workflow("m1", "wf1").unwrap();
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.workflow_ids, vec!["wf1"]);
    }

    #[test]
    fn by_tier_filters() {
        let r = ModelRiskRegister::new();
        r.register(
            "m1",
            "x",
            "y",
            RiskTier::Tier1,
            DecisionImpact::CustomerFacing,
        )
        .unwrap();
        r.register(
            "m2",
            "x",
            "y",
            RiskTier::Tier3,
            DecisionImpact::Research,
        )
        .unwrap();
        assert_eq!(r.by_tier(RiskTier::Tier1).len(), 1);
        assert_eq!(r.by_tier(RiskTier::Tier3).len(), 1);
    }

    #[test]
    fn by_status_filters() {
        let r = reg();
        r.record_validation("m1", ValidationStatus::Validated, "v1")
            .unwrap();
        assert_eq!(r.by_status(ValidationStatus::Validated).len(), 1);
        assert_eq!(r.by_status(ValidationStatus::Pending).len(), 0);
    }

    #[test]
    fn overdue_when_never_validated() {
        let r = reg();
        let now = OffsetDateTime::now_utc();
        assert_eq!(r.overdue(now).len(), 1);
    }

    #[test]
    fn overdue_when_past_interval() {
        let r = reg();
        r.record_validation("m1", ValidationStatus::Validated, "v1")
            .unwrap();
        // Tier1 = 365 days. Move 2 years forward.
        let future = OffsetDateTime::now_utc() + time::Duration::days(800);
        assert_eq!(r.overdue(future).len(), 1);
    }

    #[test]
    fn not_overdue_within_interval() {
        let r = reg();
        r.record_validation("m1", ValidationStatus::Validated, "v1")
            .unwrap();
        let now = OffsetDateTime::now_utc();
        assert_eq!(r.overdue(now).len(), 0);
    }

    #[test]
    fn open_findings_filters_closed() {
        let r = reg();
        let f1 = Finding::open(FindingSeverity::High, "a");
        let f2 = Finding::open(FindingSeverity::Low, "b");
        let id1 = f1.finding_id;
        r.add_finding("m1", f1).unwrap();
        r.add_finding("m1", f2).unwrap();
        r.close_finding("m1", id1).unwrap();
        let e = r.lookup("m1").unwrap();
        assert_eq!(e.open_findings().len(), 1);
    }

    #[test]
    fn highest_open_severity_picks_critical() {
        let r = reg();
        r.add_finding("m1", Finding::open(FindingSeverity::Low, "a"))
            .unwrap();
        r.add_finding("m1", Finding::open(FindingSeverity::Critical, "b"))
            .unwrap();
        r.add_finding("m1", Finding::open(FindingSeverity::Medium, "c"))
            .unwrap();
        assert_eq!(
            r.lookup("m1").unwrap().highest_open_severity(),
            Some(FindingSeverity::Critical)
        );
    }

    #[test]
    fn revalidation_interval_per_tier() {
        assert_eq!(RiskTier::Tier1.revalidation_interval_days(), 365);
        assert_eq!(RiskTier::Tier2.revalidation_interval_days(), 730);
        assert_eq!(RiskTier::Tier3.revalidation_interval_days(), 1095);
        assert_eq!(RiskTier::Tier4.revalidation_interval_days(), 1825);
    }

    #[test]
    fn finding_serde() {
        let f = Finding::open(FindingSeverity::High, "x");
        let j = serde_json::to_string(&f).unwrap();
        let p: Finding = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn entry_serde() {
        let r = reg();
        let e = r.lookup("m1").unwrap();
        let j = serde_json::to_string(&e).unwrap();
        let p: ModelEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }

    #[test]
    fn risk_tier_serde() {
        for t in [
            RiskTier::Tier1,
            RiskTier::Tier2,
            RiskTier::Tier3,
            RiskTier::Tier4,
        ] {
            let j = serde_json::to_string(&t).unwrap();
            let p: RiskTier = serde_json::from_str(&j).unwrap();
            assert_eq!(p, t);
        }
    }

    #[test]
    fn validation_status_serde() {
        for s in [
            ValidationStatus::Validated,
            ValidationStatus::InValidation,
            ValidationStatus::LimitationsApproved,
            ValidationStatus::NotApproved,
            ValidationStatus::Pending,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ValidationStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn decision_impact_serde() {
        for d in [
            DecisionImpact::CustomerFacing,
            DecisionImpact::InternalOperational,
            DecisionImpact::RegulatoryReporting,
            DecisionImpact::Research,
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let p: DecisionImpact = serde_json::from_str(&j).unwrap();
            assert_eq!(p, d);
        }
    }

    #[test]
    fn registry_len_tracks() {
        let r = reg();
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = reg();
        assert!(r.lookup("ghost").is_none());
    }

    #[test]
    fn finding_severity_rank_critical_lowest() {
        assert!(severity_rank(FindingSeverity::Critical) < severity_rank(FindingSeverity::Info));
    }
}
