//! Enterprise risk register.
//!
//! Distinct from [`crate::model_risk_register`] (model-specific risks) and
//! [`crate::risk_appetite`] (limit / position tracking), this is the
//! **top-level enterprise risk register** that auditors and the board
//! review: every identified risk has an owner, an inherent rating, the
//! controls that mitigate it, a residual rating, and a treatment
//! decision (Accept / Mitigate / Transfer / Avoid).
//!
//! Maps to ISO 31000 (risk management), COSO ERM, NIST 800-37 (RMF), and
//! SOC 2 CC3.2 (risk identification and analysis). The register is the
//! controller-side artefact for the annual risk review and is the source
//! the board pulls from when asking "what are our top 10 risks?".
//!
//! ## Lifecycle
//!
//! `Identified → Analyzed → Treating → Monitored → Closed`
//!
//! `Identified`: someone wrote it down. `Analyzed`: rating + ownership
//! assigned. `Treating`: treatment plan in flight. `Monitored`: residual
//! risk accepted, KRI in place. `Closed`: risk is no longer applicable.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// RiskCategory
// =============================================================================

/// Top-level risk category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    /// Cyber security and data breach.
    Cyber,
    /// Operational / availability.
    Operational,
    /// Legal / regulatory.
    Regulatory,
    /// Financial / fraud / AML.
    Financial,
    /// Strategic / market / competitive.
    Strategic,
    /// Reputational / brand.
    Reputational,
    /// Third-party / vendor.
    ThirdParty,
    /// AI / ML model risk.
    Model,
    /// People / talent / HR.
    People,
    /// Environmental / physical security.
    Environmental,
}

// =============================================================================
// RiskRating
// =============================================================================

/// Standard 5-point risk rating (qualitative).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskRating {
    /// Very low.
    VeryLow,
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
    /// Very high / critical.
    VeryHigh,
}

impl RiskRating {
    /// Numeric rank (higher = worse).
    pub fn rank(self) -> u8 {
        match self {
            Self::VeryLow => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::VeryHigh => 5,
        }
    }

    /// True if the rating exceeds the controller's risk appetite without
    /// explicit board acceptance.
    pub fn is_above_appetite(self) -> bool {
        matches!(self, Self::High | Self::VeryHigh)
    }
}

// =============================================================================
// TreatmentStrategy
// =============================================================================

/// ISO 31000 risk treatment strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreatmentStrategy {
    /// Accept the risk as-is (board acceptance required if above appetite).
    Accept,
    /// Apply controls to reduce likelihood / impact.
    Mitigate,
    /// Transfer to a third party (insurance, vendor SLA).
    Transfer,
    /// Avoid by stopping the activity that creates the risk.
    Avoid,
}

// =============================================================================
// LifecycleStage
// =============================================================================

/// Risk lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskStage {
    /// Identified but not yet analyzed.
    Identified,
    /// Rating + owner + treatment decision.
    Analyzed,
    /// Treatment plan in flight.
    Treating,
    /// Residual risk accepted; KRI / KPI in place.
    Monitored,
    /// Risk no longer applicable (or accepted permanently with sign-off).
    Closed,
}

impl RiskStage {
    /// True if the risk is closed.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }
}

// =============================================================================
// ControlReference
// =============================================================================

/// Reference to a control that mitigates this risk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlReference {
    /// Control id (matches [`crate::compliance_report::ControlRef`] or local
    /// catalog).
    pub control_id: String,
    /// Brief description.
    pub description: String,
    /// Optional framework (e.g., "SOC2 CC6.1").
    pub framework: Option<String>,
}

// =============================================================================
// RiskEvent
// =============================================================================

/// One event on the risk timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RiskEvent {
    /// RFC 3339.
    pub at: String,
    /// Author.
    pub actor: String,
    /// Stage applied.
    pub stage: RiskStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// EnterpriseRisk
// =============================================================================

/// One entry in the enterprise risk register.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnterpriseRisk {
    /// Unique id (e.g., "RISK-2025-0007").
    pub risk_id: String,
    /// Tenant scope (use "global" for organisation-wide).
    pub tenant_id: String,
    /// Display title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// Category.
    pub category: RiskCategory,
    /// Risk owner (must be a named individual / team).
    pub owner: String,
    /// Inherent likelihood (without controls).
    pub inherent_likelihood: RiskRating,
    /// Inherent impact (if it occurred).
    pub inherent_impact: RiskRating,
    /// Residual likelihood after controls.
    pub residual_likelihood: RiskRating,
    /// Residual impact after controls.
    pub residual_impact: RiskRating,
    /// Treatment strategy.
    pub treatment: TreatmentStrategy,
    /// Controls applied.
    pub controls: Vec<ControlReference>,
    /// Current lifecycle stage.
    pub stage: RiskStage,
    /// Free-text treatment plan.
    pub treatment_plan: Option<String>,
    /// Board acceptance signed off (required if residual is above appetite).
    pub board_accepted: bool,
    /// RFC 3339 — first identified.
    pub identified_at: String,
    /// RFC 3339 — last reviewed (annual review is best practice).
    pub last_reviewed_at: Option<String>,
    /// RFC 3339 — closed.
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<RiskEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl EnterpriseRisk {
    /// New `Identified` risk.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        risk_id: impl Into<String>,
        tenant_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        category: RiskCategory,
        owner: impl Into<String>,
        inherent_likelihood: RiskRating,
        inherent_impact: RiskRating,
        identified_at: impl Into<String>,
    ) -> Self {
        Self {
            risk_id: risk_id.into(),
            tenant_id: tenant_id.into(),
            title: title.into(),
            description: description.into(),
            category,
            owner: owner.into(),
            inherent_likelihood,
            inherent_impact,
            // Residual defaults equal to inherent until controls are applied.
            residual_likelihood: inherent_likelihood,
            residual_impact: inherent_impact,
            treatment: TreatmentStrategy::Mitigate,
            controls: Vec::new(),
            stage: RiskStage::Identified,
            treatment_plan: None,
            board_accepted: false,
            identified_at: identified_at.into(),
            last_reviewed_at: None,
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Higher of inherent_likelihood and inherent_impact (used as the
    /// inherent overall rating).
    pub fn inherent_rating(&self) -> RiskRating {
        max_rating(self.inherent_likelihood, self.inherent_impact)
    }

    /// Higher of residual_likelihood and residual_impact.
    pub fn residual_rating(&self) -> RiskRating {
        max_rating(self.residual_likelihood, self.residual_impact)
    }

    /// True if the residual risk exceeds the controller's appetite without
    /// board acceptance.
    pub fn requires_board_attention(&self) -> bool {
        self.residual_rating().is_above_appetite() && !self.board_accepted
    }

    /// True if the annual review is overdue at `now`.
    pub fn review_overdue(&self, now: &str) -> bool {
        let anchor = self
            .last_reviewed_at
            .as_deref()
            .unwrap_or(&self.identified_at);
        match age_in_days(anchor, now) {
            Some(d) => d >= 365,
            None => false,
        }
    }
}

fn max_rating(a: RiskRating, b: RiskRating) -> RiskRating {
    if a.rank() >= b.rank() {
        a
    } else {
        b
    }
}

fn age_in_days(earlier: &str, later: &str) -> Option<i64> {
    use time::format_description::well_known::Rfc3339;
    let a = time::OffsetDateTime::parse(earlier, &Rfc3339).ok()?;
    let b = time::OffsetDateTime::parse(later, &Rfc3339).ok()?;
    Some((b - a).whole_days())
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RiskStage, to: RiskStage) -> bool {
    use RiskStage::*;
    match (from, to) {
        (Identified, Analyzed)
        | (Identified, Closed)
        | (Analyzed, Treating)
        | (Analyzed, Monitored)
        | (Analyzed, Closed)
        | (Treating, Monitored)
        | (Treating, Closed)
        | (Monitored, Treating) // re-treatment after re-emergence
        | (Monitored, Closed) => true,
        _ => false,
    }
}

// =============================================================================
// EnterpriseRiskRegister
// =============================================================================

/// Thread-safe enterprise risk register.
#[derive(Debug, Default)]
pub struct EnterpriseRiskRegister {
    inner: RwLock<HashMap<String, EnterpriseRisk>>,
}

impl EnterpriseRiskRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new risk.
    pub fn register(&self, risk: EnterpriseRisk) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        if g.contains_key(&risk.risk_id) {
            return Err(SandboxError::Other(format!(
                "risk already registered: {}",
                risk.risk_id
            )));
        }
        g.insert(risk.risk_id.clone(), risk);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        risk_id: &str,
        new_stage: RiskStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<EnterpriseRisk> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        r.stage = new_stage;
        r.events.push(RiskEvent {
            at: when.clone(),
            actor,
            stage: new_stage,
            note,
        });
        if matches!(new_stage, RiskStage::Closed) {
            r.closed_at = Some(when);
        }
        Ok(r.clone())
    }

    /// Set residual ratings (applied after controls go into effect).
    pub fn set_residual(
        &self,
        risk_id: &str,
        likelihood: RiskRating,
        impact: RiskRating,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        r.residual_likelihood = likelihood;
        r.residual_impact = impact;
        Ok(())
    }

    /// Set treatment strategy + plan.
    pub fn set_treatment(
        &self,
        risk_id: &str,
        treatment: TreatmentStrategy,
        plan: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        r.treatment = treatment;
        r.treatment_plan = plan;
        Ok(())
    }

    /// Add a control reference (deduplicated by control_id).
    pub fn add_control(
        &self,
        risk_id: &str,
        control: ControlReference,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        if !r.controls.iter().any(|c| c.control_id == control.control_id) {
            r.controls.push(control);
        }
        Ok(())
    }

    /// Mark board acceptance for a residual rating above appetite.
    pub fn record_board_acceptance(&self, risk_id: &str) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        r.board_accepted = true;
        Ok(())
    }

    /// Mark a risk as reviewed at `at`.
    pub fn mark_reviewed(&self, risk_id: &str, at: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        r.last_reviewed_at = Some(at.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, risk_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("risk register poisoned".into()))?;
        let r = g
            .get_mut(risk_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown risk {risk_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, risk_id: &str) -> Option<EnterpriseRisk> {
        let g = self.inner.read().ok()?;
        g.get(risk_id).cloned()
    }

    /// All risks.
    pub fn all(&self) -> Vec<EnterpriseRisk> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<EnterpriseRisk> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// By category.
    pub fn by_category(&self, category: RiskCategory) -> Vec<EnterpriseRisk> {
        self.all()
            .into_iter()
            .filter(|r| r.category == category)
            .collect()
    }

    /// At a stage.
    pub fn by_stage(&self, stage: RiskStage) -> Vec<EnterpriseRisk> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Top N risks by residual rating (highest first).
    pub fn top_by_residual(&self, n: usize) -> Vec<EnterpriseRisk> {
        let mut all = self.all();
        all.sort_by(|a, b| {
            b.residual_rating()
                .rank()
                .cmp(&a.residual_rating().rank())
                .then_with(|| b.inherent_rating().rank().cmp(&a.inherent_rating().rank()))
        });
        all.into_iter().take(n).collect()
    }

    /// Risks above appetite without board acceptance.
    pub fn requiring_board_attention(&self) -> Vec<EnterpriseRisk> {
        self.all()
            .into_iter()
            .filter(|r| r.requires_board_attention())
            .collect()
    }

    /// Risks whose annual review is overdue at `now`.
    pub fn review_overdue(&self, now: &str) -> Vec<EnterpriseRisk> {
        self.all()
            .into_iter()
            .filter(|r| r.review_overdue(now))
            .collect()
    }

    /// Count.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn risk(id: &str) -> EnterpriseRisk {
        EnterpriseRisk::new(
            id,
            "global",
            format!("title-{id}"),
            "description",
            RiskCategory::Cyber,
            "ciso",
            RiskRating::High,
            RiskRating::High,
            "2025-05-01T00:00:00Z",
        )
    }

    fn ctl(id: &str) -> ControlReference {
        ControlReference {
            control_id: id.into(),
            description: format!("desc-{id}"),
            framework: Some("SOC2".into()),
        }
    }

    #[test]
    fn register_and_get() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.stage, RiskStage::Identified);
        assert_eq!(g.inherent_rating(), RiskRating::High);
        // Residual defaults equal inherent.
        assert_eq!(g.residual_rating(), RiskRating::High);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        let err = r.register(risk("r1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn legal_transitions_table() {
        use RiskStage::*;
        assert!(legal_transition(Identified, Analyzed));
        assert!(legal_transition(Identified, Closed));
        assert!(legal_transition(Analyzed, Treating));
        assert!(legal_transition(Analyzed, Monitored));
        assert!(legal_transition(Treating, Monitored));
        assert!(legal_transition(Monitored, Treating));
        assert!(legal_transition(Monitored, Closed));
        // illegal
        assert!(!legal_transition(Identified, Treating));
        assert!(!legal_transition(Identified, Monitored));
        assert!(!legal_transition(Closed, Monitored));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.transition(
            "r1",
            RiskStage::Analyzed,
            "ciso",
            "rating done",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "r1",
            RiskStage::Treating,
            "ciso",
            "controls in flight",
            "2025-05-03T00:00:00Z",
        )
        .unwrap();
        let g = r
            .transition(
                "r1",
                RiskStage::Monitored,
                "ciso",
                "kri in place",
                "2025-05-15T00:00:00Z",
            )
            .unwrap();
        assert_eq!(g.stage, RiskStage::Monitored);
        assert_eq!(g.events.len(), 3);
    }

    #[test]
    fn close_terminal() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        let g = r
            .transition(
                "r1",
                RiskStage::Closed,
                "ciso",
                "no longer applicable",
                "2025-05-15T00:00:00Z",
            )
            .unwrap();
        assert_eq!(g.stage, RiskStage::Closed);
        assert!(g.stage.is_terminal());
        assert_eq!(g.closed_at.as_deref(), Some("2025-05-15T00:00:00Z"));
    }

    #[test]
    fn re_treatment_allowed() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.transition(
            "r1",
            RiskStage::Analyzed,
            "x",
            "n",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "r1",
            RiskStage::Monitored,
            "x",
            "n",
            "2025-05-03T00:00:00Z",
        )
        .unwrap();
        // Risk re-emerged → back to Treating
        let g = r
            .transition(
                "r1",
                RiskStage::Treating,
                "x",
                "re-treatment",
                "2025-06-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(g.stage, RiskStage::Treating);
    }

    #[test]
    fn illegal_transition_errors() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        let err = r
            .transition(
                "r1",
                RiskStage::Treating,
                "x",
                "skip",
                "2025-05-02T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn set_residual_updates() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.set_residual("r1", RiskRating::Low, RiskRating::Medium)
            .unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.residual_likelihood, RiskRating::Low);
        assert_eq!(g.residual_impact, RiskRating::Medium);
        assert_eq!(g.residual_rating(), RiskRating::Medium);
    }

    #[test]
    fn set_treatment_updates() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.set_treatment(
            "r1",
            TreatmentStrategy::Transfer,
            Some("cyber insurance policy".into()),
        )
        .unwrap();
        let g = r.get("r1").unwrap();
        assert_eq!(g.treatment, TreatmentStrategy::Transfer);
        assert_eq!(g.treatment_plan.as_deref(), Some("cyber insurance policy"));
    }

    #[test]
    fn add_control_dedupes() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.add_control("r1", ctl("CC6.1")).unwrap();
        r.add_control("r1", ctl("CC6.1")).unwrap();
        r.add_control("r1", ctl("CC7.2")).unwrap();
        assert_eq!(r.get("r1").unwrap().controls.len(), 2);
    }

    #[test]
    fn record_board_acceptance() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        // High residual with no acceptance → requires board attention.
        assert!(r.get("r1").unwrap().requires_board_attention());
        r.record_board_acceptance("r1").unwrap();
        assert!(!r.get("r1").unwrap().requires_board_attention());
    }

    #[test]
    fn mark_reviewed() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.mark_reviewed("r1", "2025-12-01T00:00:00Z").unwrap();
        assert_eq!(
            r.get("r1").unwrap().last_reviewed_at.as_deref(),
            Some("2025-12-01T00:00:00Z")
        );
    }

    #[test]
    fn review_overdue_uses_identified_when_no_review() {
        let r = risk("r1"); // identified 2025-05-01
        assert!(r.review_overdue("2026-05-15T00:00:00Z"));
        assert!(!r.review_overdue("2025-12-01T00:00:00Z"));
    }

    #[test]
    fn review_overdue_uses_last_reviewed_when_present() {
        let reg = EnterpriseRiskRegister::new();
        reg.register(risk("r1")).unwrap();
        reg.mark_reviewed("r1", "2025-12-01T00:00:00Z").unwrap();
        let g = reg.get("r1").unwrap();
        assert!(!g.review_overdue("2026-06-01T00:00:00Z"));
        assert!(g.review_overdue("2026-12-15T00:00:00Z"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        r.add_tag("r1", "top10").unwrap();
        r.add_tag("r1", "top10").unwrap();
        r.add_tag("r1", "board").unwrap();
        assert_eq!(r.get("r1").unwrap().tags, vec!["top10", "board"]);
    }

    #[test]
    fn unknown_risk_errors() {
        let r = EnterpriseRiskRegister::new();
        let err = r.set_residual("nope", RiskRating::Low, RiskRating::Low).unwrap_err();
        assert!(format!("{err}").contains("unknown risk"));
    }

    #[test]
    fn for_tenant_by_category_by_stage_filters() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap();
        let mut other = risk("r2");
        other.tenant_id = "tenant-b".into();
        other.category = RiskCategory::Financial;
        r.register(other).unwrap();
        r.transition(
            "r2",
            RiskStage::Closed,
            "x",
            "n",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(r.for_tenant("global").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.by_category(RiskCategory::Cyber).len(), 1);
        assert_eq!(r.by_category(RiskCategory::Financial).len(), 1);
        assert_eq!(r.by_stage(RiskStage::Identified).len(), 1);
        assert_eq!(r.by_stage(RiskStage::Closed).len(), 1);
    }

    #[test]
    fn top_by_residual_orders_descending() {
        let r = EnterpriseRiskRegister::new();
        let mut a = risk("a");
        a.residual_likelihood = RiskRating::Low;
        a.residual_impact = RiskRating::Low;
        let mut b = risk("b");
        b.residual_likelihood = RiskRating::High;
        b.residual_impact = RiskRating::Medium;
        let mut c = risk("c");
        c.residual_likelihood = RiskRating::VeryHigh;
        c.residual_impact = RiskRating::Medium;
        r.register(a).unwrap();
        r.register(b).unwrap();
        r.register(c).unwrap();
        let top = r.top_by_residual(3);
        let ids: Vec<_> = top.iter().map(|r| r.risk_id.clone()).collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
    }

    #[test]
    fn requiring_board_attention_filters() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap(); // High residual, not accepted
        let mut accepted = risk("r2"); // High residual, accepted
        r.register(accepted.clone()).unwrap();
        r.record_board_acceptance("r2").unwrap();
        let mut low_risk = risk("r3");
        low_risk.residual_likelihood = RiskRating::Low;
        low_risk.residual_impact = RiskRating::Low;
        r.register(low_risk).unwrap();
        let _ = &mut accepted; // silence unused warning
        let need = r.requiring_board_attention();
        let ids: Vec<_> = need.iter().map(|r| r.risk_id.clone()).collect();
        assert_eq!(ids, vec!["r1"]);
    }

    #[test]
    fn review_overdue_query() {
        let r = EnterpriseRiskRegister::new();
        r.register(risk("r1")).unwrap(); // identified 2025-05-01
        let mut other = risk("r2");
        other.identified_at = "2026-04-01T00:00:00Z".into();
        r.register(other).unwrap();
        let due = r.review_overdue("2026-06-01T00:00:00Z");
        let ids: Vec<_> = due.iter().map(|r| r.risk_id.clone()).collect();
        assert_eq!(ids, vec!["r1"]);
    }

    #[test]
    fn rating_helpers() {
        assert!(RiskRating::High.is_above_appetite());
        assert!(RiskRating::VeryHigh.is_above_appetite());
        assert!(!RiskRating::Medium.is_above_appetite());
        assert!(RiskRating::High.rank() > RiskRating::Medium.rank());
        assert!(RiskRating::VeryHigh.rank() > RiskRating::High.rank());
    }

    #[test]
    fn stage_helpers() {
        assert!(RiskStage::Closed.is_terminal());
        assert!(!RiskStage::Identified.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = EnterpriseRiskRegister::new();
        assert_eq!(r.count(), 0);
        r.register(risk("r1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn risk_serde() {
        let r = risk("r1");
        let j = serde_json::to_string(&r).unwrap();
        let back: EnterpriseRisk = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enums_serde() {
        for c in [
            RiskCategory::Cyber,
            RiskCategory::Operational,
            RiskCategory::Regulatory,
            RiskCategory::Financial,
            RiskCategory::Strategic,
            RiskCategory::Reputational,
            RiskCategory::ThirdParty,
            RiskCategory::Model,
            RiskCategory::People,
            RiskCategory::Environmental,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<RiskCategory>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
        for r in [
            RiskRating::VeryLow,
            RiskRating::Low,
            RiskRating::Medium,
            RiskRating::High,
            RiskRating::VeryHigh,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<RiskRating>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
        for t in [
            TreatmentStrategy::Accept,
            TreatmentStrategy::Mitigate,
            TreatmentStrategy::Transfer,
            TreatmentStrategy::Avoid,
        ] {
            assert_eq!(
                t,
                serde_json::from_str::<TreatmentStrategy>(&serde_json::to_string(&t).unwrap())
                    .unwrap()
            );
        }
    }
}
