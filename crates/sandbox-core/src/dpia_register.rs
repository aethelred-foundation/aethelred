//! Data Protection Impact Assessment (DPIA) register.
//!
//! Maps to **GDPR Article 35**, ICO DPIA guidance, and CCPA Risk
//! Assessments. Whenever a high-risk processing activity (large-scale
//! processing of special-category data, automated decision-making,
//! systematic monitoring) is introduced, the controller must run a DPIA
//! that identifies risks, mitigations, and residual risk — and re-run it
//! when the processing changes materially.
//!
//! This registry is the system of record for "did we do the DPIA, what
//! did it find, and was it approved?" It tracks the assessment lifecycle
//! `Draft → InReview → Approved → InForce → Superseded` (with `Rejected`
//! as an alternative terminal from `InReview`).
//!
//! Distinct from [`crate::gdpr_erasure`] (operational right-to-erasure)
//! and [`crate::customer_consent`] (per-subject consent records); this is
//! the **controller-side** assessment that authorises the entire
//! processing activity in the first place.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AssessmentStage
// =============================================================================

/// DPIA lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStage {
    /// Author drafting the assessment.
    Draft,
    /// Submitted to DPO / privacy team for review.
    InReview,
    /// Approved but not yet effective.
    Approved,
    /// Currently in force — the authoritative version.
    InForce,
    /// A newer DPIA replaced this one.
    Superseded,
    /// Rejected at review; processing must not proceed.
    Rejected,
}

impl AssessmentStage {
    /// True if processing is authorised under this stage.
    pub fn is_authorising(self) -> bool {
        matches!(self, Self::InForce)
    }

    /// True if no further transitions are expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::Rejected)
    }
}

// =============================================================================
// RiskLevel
// =============================================================================

/// Residual risk after mitigations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Acceptable — proceed.
    Low,
    /// Heightened — proceed with specific safeguards.
    Medium,
    /// Significant — DPO sign-off required.
    High,
    /// Unacceptable — must escalate to regulator under GDPR Art 36.
    Critical,
}

impl RiskLevel {
    /// True if regulator consultation is required (GDPR Art 36).
    pub fn requires_regulator_consultation(self) -> bool {
        matches!(self, Self::Critical)
    }
}

// =============================================================================
// LegalBasis
// =============================================================================

/// GDPR Art 6 legal basis for the processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalBasis {
    /// Subject consent.
    Consent,
    /// Performance of a contract.
    Contract,
    /// Legal obligation.
    LegalObligation,
    /// Vital interests of the subject.
    VitalInterests,
    /// Public interest / official authority.
    PublicInterest,
    /// Legitimate interests of the controller.
    LegitimateInterest,
}

// =============================================================================
// IdentifiedRisk
// =============================================================================

/// One identified risk with mitigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentifiedRisk {
    /// Stable id within the DPIA.
    pub risk_id: String,
    /// Description of the risk.
    pub description: String,
    /// Inherent risk before mitigation.
    pub inherent: RiskLevel,
    /// Residual risk after mitigation.
    pub residual: RiskLevel,
    /// Mitigation summary.
    pub mitigation: String,
}

// =============================================================================
// AssessmentEvent
// =============================================================================

/// One event in the DPIA timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessmentEvent {
    /// RFC 3339 — event time.
    pub at: String,
    /// Author / actor.
    pub actor: String,
    /// Stage applied.
    pub stage: AssessmentStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// Dpia
// =============================================================================

/// One Data Protection Impact Assessment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dpia {
    /// Unique id.
    pub dpia_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Name of the processing activity (e.g., "Fraud-scoring model v2").
    pub activity_name: String,
    /// One-paragraph description.
    pub description: String,
    /// Controller team / owner.
    pub owner: String,
    /// Data Protection Officer reviewer (if assigned).
    pub dpo: Option<String>,
    /// Legal basis under GDPR Art 6.
    pub legal_basis: LegalBasis,
    /// Categories of data processed (free text but recommended:
    /// "personal", "special_category", "biometric", "financial").
    pub data_categories: Vec<String>,
    /// Identified risks with mitigation.
    pub risks: Vec<IdentifiedRisk>,
    /// Highest residual risk across all `risks` — recomputed by the
    /// registry whenever risks change.
    pub overall_residual: RiskLevel,
    /// Current lifecycle stage.
    pub stage: AssessmentStage,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — approved (set when stage moves to Approved).
    pub approved_at: Option<String>,
    /// RFC 3339 — entered force (set when stage moves to InForce).
    pub effective_at: Option<String>,
    /// RFC 3339 — superseded (set when stage moves to Superseded).
    pub superseded_at: Option<String>,
    /// Successor DPIA id if superseded.
    pub successor: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Event timeline.
    pub events: Vec<AssessmentEvent>,
}

impl Dpia {
    /// Construct a new Draft DPIA.
    pub fn new(
        dpia_id: impl Into<String>,
        tenant_id: impl Into<String>,
        activity_name: impl Into<String>,
        description: impl Into<String>,
        owner: impl Into<String>,
        legal_basis: LegalBasis,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            dpia_id: dpia_id.into(),
            tenant_id: tenant_id.into(),
            activity_name: activity_name.into(),
            description: description.into(),
            owner: owner.into(),
            dpo: None,
            legal_basis,
            data_categories: Vec::new(),
            risks: Vec::new(),
            overall_residual: RiskLevel::Low,
            stage: AssessmentStage::Draft,
            drafted_at: drafted_at.into(),
            approved_at: None,
            effective_at: None,
            superseded_at: None,
            successor: None,
            tags: Vec::new(),
            events: Vec::new(),
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: AssessmentStage, to: AssessmentStage) -> bool {
    use AssessmentStage::*;
    match (from, to) {
        (Draft, InReview)
        | (Draft, Rejected)
        | (InReview, Approved)
        | (InReview, Rejected)
        | (InReview, Draft)
        | (Approved, InForce)
        | (Approved, Draft)
        | (InForce, Superseded) => true,
        _ => false,
    }
}

fn recompute_residual(risks: &[IdentifiedRisk]) -> RiskLevel {
    let order = |r: RiskLevel| match r {
        RiskLevel::Low => 1,
        RiskLevel::Medium => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    };
    risks
        .iter()
        .map(|r| r.residual)
        .max_by_key(|r| order(*r))
        .unwrap_or(RiskLevel::Low)
}

// =============================================================================
// DpiaRegister
// =============================================================================

/// Thread-safe DPIA register.
#[derive(Debug, Default)]
pub struct DpiaRegister {
    inner: RwLock<HashMap<String, Dpia>>,
}

impl DpiaRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new DPIA.
    pub fn register(&self, dpia: Dpia) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        if g.contains_key(&dpia.dpia_id) {
            return Err(SandboxError::Other(format!(
                "dpia already registered: {}",
                dpia.dpia_id
            )));
        }
        g.insert(dpia.dpia_id.clone(), dpia);
        Ok(())
    }

    /// Add an identified risk and recompute the overall residual.
    pub fn add_risk(&self, dpia_id: &str, risk: IdentifiedRisk) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(dpia_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {dpia_id}")))?;
        d.risks.push(risk);
        d.overall_residual = recompute_residual(&d.risks);
        Ok(())
    }

    /// Add a data category (deduplicated).
    pub fn add_data_category(
        &self,
        dpia_id: &str,
        category: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(dpia_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {dpia_id}")))?;
        let cat = category.into();
        if !d.data_categories.contains(&cat) {
            d.data_categories.push(cat);
        }
        Ok(())
    }

    /// Set the DPO reviewer.
    pub fn set_dpo(&self, dpia_id: &str, dpo: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(dpia_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {dpia_id}")))?;
        d.dpo = Some(dpo.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, dpia_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(dpia_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {dpia_id}")))?;
        let tag = tag.into();
        if !d.tags.contains(&tag) {
            d.tags.push(tag);
        }
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        dpia_id: &str,
        new_stage: AssessmentStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<Dpia> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(dpia_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {dpia_id}")))?;
        if !legal_transition(d.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal dpia transition {:?} -> {:?}",
                d.stage, new_stage
            )));
        }
        let when = at.into();
        d.stage = new_stage;
        d.events.push(AssessmentEvent {
            at: when.clone(),
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        match new_stage {
            AssessmentStage::Approved => d.approved_at = Some(when),
            AssessmentStage::InForce => d.effective_at = Some(when),
            AssessmentStage::Superseded => d.superseded_at = Some(when),
            _ => {}
        }
        Ok(d.clone())
    }

    /// Mark `older` Superseded by `newer`. `newer` must already exist; both
    /// must be in the same tenant. Sets `older.superseded_at`,
    /// `older.successor`, transitions `older` to `Superseded` (must currently
    /// be `InForce`).
    pub fn supersede(
        &self,
        older: &str,
        newer: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<Dpia> {
        let when = at.into();
        let actor = actor.into();
        // Validate the newer exists and lives in the same tenant.
        let newer_tenant = {
            let g = self
                .inner
                .read()
                .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
            let n = g
                .get(newer)
                .ok_or_else(|| SandboxError::Other(format!("unknown dpia {newer}")))?;
            n.tenant_id.clone()
        };
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("dpia register poisoned".into()))?;
        let d = g
            .get_mut(older)
            .ok_or_else(|| SandboxError::Other(format!("unknown dpia {older}")))?;
        if d.tenant_id != newer_tenant {
            return Err(SandboxError::Other(format!(
                "tenant mismatch: {} vs {}",
                d.tenant_id, newer_tenant
            )));
        }
        if !legal_transition(d.stage, AssessmentStage::Superseded) {
            return Err(SandboxError::Other(format!(
                "cannot supersede {older}: stage is {:?}",
                d.stage
            )));
        }
        d.stage = AssessmentStage::Superseded;
        d.superseded_at = Some(when.clone());
        d.successor = Some(newer.to_string());
        d.events.push(AssessmentEvent {
            at: when,
            actor,
            stage: AssessmentStage::Superseded,
            note: format!("superseded by {newer}"),
        });
        Ok(d.clone())
    }

    /// Look up.
    pub fn get(&self, dpia_id: &str) -> Option<Dpia> {
        let g = self.inner.read().ok()?;
        g.get(dpia_id).cloned()
    }

    /// All entries.
    pub fn all(&self) -> Vec<Dpia> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// All entries for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<Dpia> {
        self.all()
            .into_iter()
            .filter(|d| d.tenant_id == tenant_id)
            .collect()
    }

    /// All entries at a given stage.
    pub fn by_stage(&self, stage: AssessmentStage) -> Vec<Dpia> {
        self.all().into_iter().filter(|d| d.stage == stage).collect()
    }

    /// All entries currently authorising processing.
    pub fn in_force(&self) -> Vec<Dpia> {
        self.by_stage(AssessmentStage::InForce)
    }

    /// All entries with residual risk requiring regulator consultation.
    pub fn requiring_regulator_consultation(&self) -> Vec<Dpia> {
        self.all()
            .into_iter()
            .filter(|d| d.overall_residual.requires_regulator_consultation())
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

    fn dpia(id: &str) -> Dpia {
        Dpia::new(
            id,
            "tenant-a",
            format!("activity-{id}"),
            "description",
            "privacy-team",
            LegalBasis::LegitimateInterest,
            "2025-05-01T00:00:00Z",
        )
    }

    fn risk(id: &str, inherent: RiskLevel, residual: RiskLevel) -> IdentifiedRisk {
        IdentifiedRisk {
            risk_id: id.into(),
            description: format!("risk-{id}"),
            inherent,
            residual,
            mitigation: "mitigation".into(),
        }
    }

    #[test]
    fn register_and_get() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        let d = r.get("d1").unwrap();
        assert_eq!(d.stage, AssessmentStage::Draft);
        assert_eq!(d.overall_residual, RiskLevel::Low);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        let err = r.register(dpia("d1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn add_risk_recomputes_overall() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        r.add_risk("d1", risk("r1", RiskLevel::Medium, RiskLevel::Low))
            .unwrap();
        assert_eq!(r.get("d1").unwrap().overall_residual, RiskLevel::Low);
        r.add_risk("d1", risk("r2", RiskLevel::High, RiskLevel::High))
            .unwrap();
        assert_eq!(r.get("d1").unwrap().overall_residual, RiskLevel::High);
        r.add_risk("d1", risk("r3", RiskLevel::Critical, RiskLevel::Critical))
            .unwrap();
        assert_eq!(r.get("d1").unwrap().overall_residual, RiskLevel::Critical);
    }

    #[test]
    fn add_data_category_dedupes() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        r.add_data_category("d1", "personal").unwrap();
        r.add_data_category("d1", "personal").unwrap();
        r.add_data_category("d1", "special_category").unwrap();
        assert_eq!(
            r.get("d1").unwrap().data_categories,
            vec!["personal", "special_category"]
        );
    }

    #[test]
    fn set_dpo_set_tag() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        r.set_dpo("d1", "dpo@example.test").unwrap();
        r.add_tag("d1", "high-risk").unwrap();
        r.add_tag("d1", "high-risk").unwrap(); // dedupe
        let d = r.get("d1").unwrap();
        assert_eq!(d.dpo.as_deref(), Some("dpo@example.test"));
        assert_eq!(d.tags, vec!["high-risk"]);
    }

    #[test]
    fn legal_transition_table() {
        use AssessmentStage::*;
        assert!(legal_transition(Draft, InReview));
        assert!(legal_transition(Draft, Rejected));
        assert!(legal_transition(InReview, Approved));
        assert!(legal_transition(InReview, Rejected));
        assert!(legal_transition(InReview, Draft)); // returned for revisions
        assert!(legal_transition(Approved, InForce));
        assert!(legal_transition(Approved, Draft));
        assert!(legal_transition(InForce, Superseded));
        // illegal moves
        assert!(!legal_transition(Draft, Approved));
        assert!(!legal_transition(InForce, Approved));
        assert!(!legal_transition(Rejected, InReview));
        assert!(!legal_transition(Superseded, InForce));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        r.transition(
            "d1",
            AssessmentStage::InReview,
            "owner",
            "submit",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "d1",
            AssessmentStage::Approved,
            "dpo",
            "approve",
            "2025-05-03T00:00:00Z",
        )
        .unwrap();
        r.transition(
            "d1",
            AssessmentStage::InForce,
            "ops",
            "deploy",
            "2025-05-04T00:00:00Z",
        )
        .unwrap();
        let d = r.get("d1").unwrap();
        assert_eq!(d.stage, AssessmentStage::InForce);
        assert_eq!(d.approved_at.as_deref(), Some("2025-05-03T00:00:00Z"));
        assert_eq!(d.effective_at.as_deref(), Some("2025-05-04T00:00:00Z"));
        assert_eq!(d.events.len(), 3);
    }

    #[test]
    fn rejected_path() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        r.transition(
            "d1",
            AssessmentStage::InReview,
            "owner",
            "submit",
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        let d = r
            .transition(
                "d1",
                AssessmentStage::Rejected,
                "dpo",
                "unmitigable risk",
                "2025-05-03T00:00:00Z",
            )
            .unwrap();
        assert_eq!(d.stage, AssessmentStage::Rejected);
        assert!(!d.stage.is_authorising());
        assert!(d.stage.is_terminal());
    }

    #[test]
    fn illegal_transition_errors() {
        let r = DpiaRegister::new();
        r.register(dpia("d1")).unwrap();
        let err = r
            .transition(
                "d1",
                AssessmentStage::InForce,
                "owner",
                "skip",
                "2025-05-02T00:00:00Z",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal dpia transition"));
    }

    #[test]
    fn supersede_links_both() {
        let r = DpiaRegister::new();
        r.register(dpia("v1")).unwrap();
        r.register(dpia("v2")).unwrap();
        // Drive v1 to InForce
        r.transition("v1", AssessmentStage::InReview, "x", "n", "2025-05-02T00:00:00Z")
            .unwrap();
        r.transition("v1", AssessmentStage::Approved, "x", "n", "2025-05-03T00:00:00Z")
            .unwrap();
        r.transition("v1", AssessmentStage::InForce, "x", "n", "2025-05-04T00:00:00Z")
            .unwrap();
        let s = r
            .supersede("v1", "v2", "x", "2025-05-05T00:00:00Z")
            .unwrap();
        assert_eq!(s.stage, AssessmentStage::Superseded);
        assert_eq!(s.successor.as_deref(), Some("v2"));
        assert_eq!(s.superseded_at.as_deref(), Some("2025-05-05T00:00:00Z"));
    }

    #[test]
    fn supersede_requires_in_force() {
        let r = DpiaRegister::new();
        r.register(dpia("v1")).unwrap();
        r.register(dpia("v2")).unwrap();
        let err = r
            .supersede("v1", "v2", "x", "2025-05-05T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("cannot supersede"));
    }

    #[test]
    fn supersede_unknown_newer_errors() {
        let r = DpiaRegister::new();
        r.register(dpia("v1")).unwrap();
        let err = r
            .supersede("v1", "v9", "x", "2025-05-05T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown dpia"));
    }

    #[test]
    fn supersede_tenant_mismatch_errors() {
        let r = DpiaRegister::new();
        r.register(dpia("v1")).unwrap();
        let mut other = dpia("v2");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        // Drive v1 to InForce
        r.transition("v1", AssessmentStage::InReview, "x", "n", "2025-05-02T00:00:00Z")
            .unwrap();
        r.transition("v1", AssessmentStage::Approved, "x", "n", "2025-05-03T00:00:00Z")
            .unwrap();
        r.transition("v1", AssessmentStage::InForce, "x", "n", "2025-05-04T00:00:00Z")
            .unwrap();
        let err = r
            .supersede("v1", "v2", "x", "2025-05-05T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn unknown_dpia_errors() {
        let r = DpiaRegister::new();
        let err = r.set_dpo("nope", "dpo").unwrap_err();
        assert!(format!("{err}").contains("unknown dpia"));
    }

    #[test]
    fn for_tenant_filters() {
        let r = DpiaRegister::new();
        r.register(dpia("a")).unwrap();
        let mut other = dpia("b");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_stage_in_force_helpers() {
        let r = DpiaRegister::new();
        r.register(dpia("a")).unwrap();
        r.register(dpia("b")).unwrap();
        // a → InForce
        r.transition("a", AssessmentStage::InReview, "x", "n", "2025-05-02T00:00:00Z")
            .unwrap();
        r.transition("a", AssessmentStage::Approved, "x", "n", "2025-05-03T00:00:00Z")
            .unwrap();
        r.transition("a", AssessmentStage::InForce, "x", "n", "2025-05-04T00:00:00Z")
            .unwrap();
        assert_eq!(r.in_force().len(), 1);
        assert_eq!(r.by_stage(AssessmentStage::Draft).len(), 1);
    }

    #[test]
    fn requiring_regulator_consultation() {
        let r = DpiaRegister::new();
        r.register(dpia("a")).unwrap();
        r.register(dpia("b")).unwrap();
        r.add_risk("a", risk("r1", RiskLevel::Critical, RiskLevel::Critical))
            .unwrap();
        r.add_risk("b", risk("r1", RiskLevel::High, RiskLevel::Medium))
            .unwrap();
        let need = r.requiring_regulator_consultation();
        assert_eq!(need.len(), 1);
        assert_eq!(need[0].dpia_id, "a");
    }

    #[test]
    fn risk_helpers() {
        assert!(RiskLevel::Critical.requires_regulator_consultation());
        assert!(!RiskLevel::High.requires_regulator_consultation());
        assert!(!RiskLevel::Low.requires_regulator_consultation());
    }

    #[test]
    fn stage_helpers() {
        assert!(AssessmentStage::InForce.is_authorising());
        for s in [
            AssessmentStage::Draft,
            AssessmentStage::InReview,
            AssessmentStage::Approved,
            AssessmentStage::Superseded,
            AssessmentStage::Rejected,
        ] {
            assert!(!s.is_authorising());
        }
        assert!(AssessmentStage::Superseded.is_terminal());
        assert!(AssessmentStage::Rejected.is_terminal());
        assert!(!AssessmentStage::Draft.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = DpiaRegister::new();
        assert_eq!(r.count(), 0);
        r.register(dpia("a")).unwrap();
        r.register(dpia("b")).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn dpia_serde() {
        let d = dpia("d1");
        let j = serde_json::to_string(&d).unwrap();
        let back: Dpia = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn risk_serde() {
        let r = risk("r1", RiskLevel::High, RiskLevel::Medium);
        let j = serde_json::to_string(&r).unwrap();
        let back: IdentifiedRisk = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            AssessmentStage::Draft,
            AssessmentStage::InReview,
            AssessmentStage::Approved,
            AssessmentStage::InForce,
            AssessmentStage::Superseded,
            AssessmentStage::Rejected,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<AssessmentStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for r in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<RiskLevel>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
        for b in [
            LegalBasis::Consent,
            LegalBasis::Contract,
            LegalBasis::LegalObligation,
            LegalBasis::VitalInterests,
            LegalBasis::PublicInterest,
            LegalBasis::LegitimateInterest,
        ] {
            assert_eq!(
                b,
                serde_json::from_str::<LegalBasis>(&serde_json::to_string(&b).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn recompute_residual_empty_is_low() {
        assert_eq!(recompute_residual(&[]), RiskLevel::Low);
    }
}
