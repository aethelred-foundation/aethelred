//! Automated-decision appeal register.
//!
//! Maps to **GDPR Article 22** (the right not to be subject to a decision
//! based solely on automated processing) and **CCPA / CPRA** automated
//! decision-making rights. When the platform makes an automated decision
//! against a subject — credit denied, claim flagged, content removed,
//! benefit terminated — the subject has a right to obtain human review
//! and to contest the decision.
//!
//! This registry is the system of record for those appeals:
//!
//! - the **original decision** (id, model, score, outcome),
//! - the **appeal request** (subject, channel, deadline),
//! - the **review process** (reviewer, evidence requested, hearing notes),
//! - the **outcome** (`Upheld`, `PartiallyOverturned`, `Overturned`).
//!
//! Distinct from [`crate::privacy_request_register`] (which is the
//! GDPR Art 15-21 rights bundle); appeals under Art 22 carry stricter
//! requirements: **meaningful human review** with the power to overturn,
//! documented criteria, and a final reasoned outcome.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AppealStage
// =============================================================================

/// Lifecycle stage of an appeal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealStage {
    /// Appeal logged.
    Filed,
    /// Subject identity verified.
    Verified,
    /// Identity verification failed; closed.
    VerificationFailed,
    /// Reviewer collecting evidence.
    EvidenceCollection,
    /// Hearing / review underway.
    UnderReview,
    /// Reviewer issued decision; original decision upheld.
    Upheld,
    /// Reviewer issued decision; original partially overturned.
    PartiallyOverturned,
    /// Reviewer issued decision; original fully overturned.
    Overturned,
    /// Subject withdrew the appeal.
    Withdrawn,
}

impl AppealStage {
    /// True if no further action is expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Upheld
                | Self::PartiallyOverturned
                | Self::Overturned
                | Self::Withdrawn
                | Self::VerificationFailed
        )
    }

    /// True if the original decision was modified.
    pub fn original_overturned(self) -> bool {
        matches!(self, Self::PartiallyOverturned | Self::Overturned)
    }
}

// =============================================================================
// DecisionImpact
// =============================================================================

/// Severity of impact on the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionImpact {
    /// Subject saw an informational change (e.g., recommendation).
    Informational,
    /// Subject's experience was affected (e.g., feature gated).
    Service,
    /// Subject's access to product / service was constrained.
    Restrictive,
    /// Subject suffered legal or significant economic effect.
    LegalOrSignificant,
}

// =============================================================================
// OriginalDecision
// =============================================================================

/// Snapshot of the automated decision being appealed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OriginalDecision {
    /// Decision id (e.g., from [`crate::case_management`]).
    pub decision_id: String,
    /// Model id that produced the decision.
    pub model_id: String,
    /// Model version.
    pub model_version: String,
    /// Decision outcome label (e.g., "deny", "approve", "flag").
    pub outcome: String,
    /// Optional score / confidence.
    pub score: Option<f64>,
    /// Impact on the subject.
    pub impact: DecisionImpact,
    /// RFC 3339 — when the decision was rendered.
    pub rendered_at: String,
}

// =============================================================================
// EvidenceItem
// =============================================================================

/// One piece of evidence collected during review.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceItem {
    /// Stable id within the appeal.
    pub item_id: String,
    /// Source ("subject", "system", "third-party").
    pub source: String,
    /// Brief description.
    pub description: String,
    /// RFC 3339 — collected.
    pub collected_at: String,
    /// Optional pointer / URI.
    pub reference: Option<String>,
}

// =============================================================================
// AppealEvent
// =============================================================================

/// One event on the appeal timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppealEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor (operator, reviewer, system).
    pub actor: String,
    /// Stage applied.
    pub stage: AppealStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// Appeal
// =============================================================================

/// One automated-decision appeal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Appeal {
    /// Unique id.
    pub appeal_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Subject id.
    pub subject_id: String,
    /// Original automated decision.
    pub original: OriginalDecision,
    /// Reviewer assigned (must be human).
    pub reviewer: Option<String>,
    /// Channel ("portal", "email", "letter", "in_person").
    pub channel: String,
    /// Verification method.
    pub verification_method: Option<String>,
    /// Current stage.
    pub stage: AppealStage,
    /// RFC 3339 — filed.
    pub filed_at: String,
    /// RFC 3339 — statutory / contractual deadline for resolution.
    pub deadline_at: String,
    /// RFC 3339 — terminal date.
    pub closed_at: Option<String>,
    /// Reasoned outcome explanation issued to subject.
    pub reasoned_outcome: Option<String>,
    /// Replacement decision if overturned.
    pub replacement_outcome: Option<String>,
    /// Evidence items collected during review.
    pub evidence: Vec<EvidenceItem>,
    /// Event timeline.
    pub events: Vec<AppealEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl Appeal {
    /// New `Filed` appeal.
    pub fn new(
        appeal_id: impl Into<String>,
        tenant_id: impl Into<String>,
        subject_id: impl Into<String>,
        original: OriginalDecision,
        channel: impl Into<String>,
        filed_at: impl Into<String>,
        deadline_at: impl Into<String>,
    ) -> Self {
        Self {
            appeal_id: appeal_id.into(),
            tenant_id: tenant_id.into(),
            subject_id: subject_id.into(),
            original,
            reviewer: None,
            channel: channel.into(),
            verification_method: None,
            stage: AppealStage::Filed,
            filed_at: filed_at.into(),
            deadline_at: deadline_at.into(),
            closed_at: None,
            reasoned_outcome: None,
            replacement_outcome: None,
            evidence: Vec::new(),
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if `now >= deadline_at` and not yet terminal.
    pub fn is_overdue(&self, now: &str) -> bool {
        if self.stage.is_terminal() {
            return false;
        }
        now >= self.deadline_at.as_str()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: AppealStage, to: AppealStage) -> bool {
    use AppealStage::*;
    match (from, to) {
        (Filed, Verified)
        | (Filed, VerificationFailed)
        | (Filed, Withdrawn)
        | (Verified, EvidenceCollection)
        | (Verified, UnderReview)
        | (Verified, Withdrawn)
        | (EvidenceCollection, UnderReview)
        | (EvidenceCollection, Withdrawn)
        | (UnderReview, Upheld)
        | (UnderReview, PartiallyOverturned)
        | (UnderReview, Overturned)
        | (UnderReview, Withdrawn) => true,
        _ => false,
    }
}

// =============================================================================
// AppealRegister
// =============================================================================

/// Thread-safe register of automated-decision appeals.
#[derive(Debug, Default)]
pub struct AppealRegister {
    inner: RwLock<HashMap<String, Appeal>>,
}

impl AppealRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// File a new appeal. Errors if `appeal_id` collides or initial stage
    /// is not Filed.
    pub fn file(&self, appeal: Appeal) -> SandboxResult<()> {
        if !matches!(appeal.stage, AppealStage::Filed) {
            return Err(SandboxError::Other(format!(
                "appeal must start Filed, got {:?}",
                appeal.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        if g.contains_key(&appeal.appeal_id) {
            return Err(SandboxError::Other(format!(
                "appeal already filed: {}",
                appeal.appeal_id
            )));
        }
        g.insert(appeal.appeal_id.clone(), appeal);
        Ok(())
    }

    /// Apply a stage transition. For terminal stages with an outcome,
    /// caller may set `replacement` — required when stage is
    /// `PartiallyOverturned` or `Overturned`.
    pub fn transition(
        &self,
        appeal_id: &str,
        new_stage: AppealStage,
        actor: impl Into<String>,
        note: impl Into<String>,
        at: impl Into<String>,
        reasoned_outcome: Option<String>,
        replacement: Option<String>,
    ) -> SandboxResult<Appeal> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        let a = g
            .get_mut(appeal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown appeal {appeal_id}")))?;
        if !legal_transition(a.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                a.stage, new_stage
            )));
        }
        if matches!(
            new_stage,
            AppealStage::Overturned | AppealStage::PartiallyOverturned
        ) && replacement.is_none()
        {
            return Err(SandboxError::Other(format!(
                "{:?} requires a replacement outcome",
                new_stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        a.stage = new_stage;
        a.events.push(AppealEvent {
            at: when.clone(),
            actor,
            stage: new_stage,
            note: note.clone(),
        });
        if let Some(r) = reasoned_outcome {
            a.reasoned_outcome = Some(r);
        }
        if let Some(r) = replacement {
            a.replacement_outcome = Some(r);
        }
        if new_stage.is_terminal() {
            a.closed_at = Some(when);
        }
        Ok(a.clone())
    }

    /// Assign a human reviewer.
    pub fn assign_reviewer(
        &self,
        appeal_id: &str,
        reviewer: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        let a = g
            .get_mut(appeal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown appeal {appeal_id}")))?;
        a.reviewer = Some(reviewer.into());
        Ok(())
    }

    /// Record verification method.
    pub fn set_verification(
        &self,
        appeal_id: &str,
        method: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        let a = g
            .get_mut(appeal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown appeal {appeal_id}")))?;
        a.verification_method = Some(method.into());
        Ok(())
    }

    /// Add an evidence item.
    pub fn add_evidence(
        &self,
        appeal_id: &str,
        item: EvidenceItem,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        let a = g
            .get_mut(appeal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown appeal {appeal_id}")))?;
        a.evidence.push(item);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, appeal_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("appeal register poisoned".into()))?;
        let a = g
            .get_mut(appeal_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown appeal {appeal_id}")))?;
        let tag = tag.into();
        if !a.tags.contains(&tag) {
            a.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, appeal_id: &str) -> Option<Appeal> {
        let g = self.inner.read().ok()?;
        g.get(appeal_id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<Appeal> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<Appeal> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// For a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<Appeal> {
        self.all()
            .into_iter()
            .filter(|a| a.subject_id == subject_id)
            .collect()
    }

    /// At a stage.
    pub fn by_stage(&self, stage: AppealStage) -> Vec<Appeal> {
        self.all().into_iter().filter(|a| a.stage == stage).collect()
    }

    /// Open appeals overdue at `now`.
    pub fn overdue(&self, now: &str) -> Vec<Appeal> {
        self.all().into_iter().filter(|a| a.is_overdue(now)).collect()
    }

    /// Appeals where the original was overturned (fully or partially).
    pub fn overturned(&self) -> Vec<Appeal> {
        self.all()
            .into_iter()
            .filter(|a| a.stage.original_overturned())
            .collect()
    }

    /// Appeals on decisions with `LegalOrSignificant` impact.
    pub fn high_impact(&self) -> Vec<Appeal> {
        self.all()
            .into_iter()
            .filter(|a| matches!(a.original.impact, DecisionImpact::LegalOrSignificant))
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

    fn original() -> OriginalDecision {
        OriginalDecision {
            decision_id: "dec-1".into(),
            model_id: "credit-scorer".into(),
            model_version: "v3".into(),
            outcome: "deny".into(),
            score: Some(0.42),
            impact: DecisionImpact::LegalOrSignificant,
            rendered_at: "2025-05-01T00:00:00Z".into(),
        }
    }

    fn appeal(id: &str) -> Appeal {
        Appeal::new(
            id,
            "tenant-a",
            "subject-1",
            original(),
            "portal",
            "2025-05-02T00:00:00Z",
            "2025-06-01T00:00:00Z",
        )
    }

    fn evid(id: &str) -> EvidenceItem {
        EvidenceItem {
            item_id: id.into(),
            source: "subject".into(),
            description: format!("doc-{id}"),
            collected_at: "2025-05-05T00:00:00Z".into(),
            reference: None,
        }
    }

    #[test]
    fn file_and_get() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.stage, AppealStage::Filed);
    }

    #[test]
    fn duplicate_file_errors() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        let err = r.file(appeal("a1")).unwrap_err();
        assert!(format!("{err}").contains("already filed"));
    }

    #[test]
    fn must_start_filed() {
        let mut a = appeal("a1");
        a.stage = AppealStage::UnderReview;
        let r = AppealRegister::new();
        let err = r.file(a).unwrap_err();
        assert!(format!("{err}").contains("must start Filed"));
    }

    #[test]
    fn legal_transitions() {
        use AppealStage::*;
        assert!(legal_transition(Filed, Verified));
        assert!(legal_transition(Filed, VerificationFailed));
        assert!(legal_transition(Filed, Withdrawn));
        assert!(legal_transition(Verified, EvidenceCollection));
        assert!(legal_transition(Verified, UnderReview));
        assert!(legal_transition(EvidenceCollection, UnderReview));
        assert!(legal_transition(UnderReview, Upheld));
        assert!(legal_transition(UnderReview, PartiallyOverturned));
        assert!(legal_transition(UnderReview, Overturned));
        assert!(!legal_transition(Filed, Upheld));
        assert!(!legal_transition(Verified, Upheld));
        assert!(!legal_transition(VerificationFailed, Verified));
        assert!(!legal_transition(Upheld, UnderReview));
    }

    #[test]
    fn happy_path_overturn() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.transition(
            "a1",
            AppealStage::Verified,
            "ops",
            "kba ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::EvidenceCollection,
            "reviewer",
            "request docs",
            "2025-05-04T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let a = r
            .transition(
                "a1",
                AppealStage::Overturned,
                "reviewer",
                "subject prevailed",
                "2025-05-15T00:00:00Z",
                Some("Reason: documentation supports approval".into()),
                Some("approve".into()),
            )
            .unwrap();
        assert_eq!(a.stage, AppealStage::Overturned);
        assert!(a.stage.original_overturned());
        assert_eq!(a.replacement_outcome.as_deref(), Some("approve"));
        assert!(a.reasoned_outcome.is_some());
        assert_eq!(a.events.len(), 4);
    }

    #[test]
    fn overturn_requires_replacement() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.transition(
            "a1",
            AppealStage::Verified,
            "ops",
            "ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let err = r
            .transition(
                "a1",
                AppealStage::Overturned,
                "reviewer",
                "n",
                "2025-05-15T00:00:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("requires a replacement"));
    }

    #[test]
    fn partial_overturn_requires_replacement() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.transition(
            "a1",
            AppealStage::Verified,
            "ops",
            "ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let err = r
            .transition(
                "a1",
                AppealStage::PartiallyOverturned,
                "reviewer",
                "n",
                "2025-05-15T00:00:00Z",
                None,
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("requires a replacement"));
    }

    #[test]
    fn upheld_does_not_require_replacement() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.transition(
            "a1",
            AppealStage::Verified,
            "ops",
            "ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        let a = r
            .transition(
                "a1",
                AppealStage::Upheld,
                "reviewer",
                "decision affirmed",
                "2025-05-15T00:00:00Z",
                Some("Reason: decision was correct".into()),
                None,
            )
            .unwrap();
        assert_eq!(a.stage, AppealStage::Upheld);
        assert!(!a.stage.original_overturned());
    }

    #[test]
    fn assign_reviewer_set_verification() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.assign_reviewer("a1", "Dr. Carol Reviewer").unwrap();
        r.set_verification("a1", "id_check").unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.reviewer.as_deref(), Some("Dr. Carol Reviewer"));
        assert_eq!(a.verification_method.as_deref(), Some("id_check"));
    }

    #[test]
    fn add_evidence_and_tag() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.add_evidence("a1", evid("e1")).unwrap();
        r.add_evidence("a1", evid("e2")).unwrap();
        r.add_tag("a1", "high-priority").unwrap();
        r.add_tag("a1", "high-priority").unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.evidence.len(), 2);
        assert_eq!(a.tags, vec!["high-priority"]);
    }

    #[test]
    fn unknown_appeal_errors() {
        let r = AppealRegister::new();
        let err = r.assign_reviewer("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown appeal"));
    }

    #[test]
    fn for_tenant_for_subject_filters() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        let mut other = appeal("a2");
        other.tenant_id = "tenant-b".into();
        other.subject_id = "subject-9".into();
        r.file(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_subject("subject-1").len(), 1);
        assert_eq!(r.for_subject("subject-9").len(), 1);
    }

    #[test]
    fn by_stage_filters() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.file(appeal("a2")).unwrap();
        r.transition(
            "a1",
            AppealStage::Withdrawn,
            "subject",
            "n",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        assert_eq!(r.by_stage(AppealStage::Filed).len(), 1);
        assert_eq!(r.by_stage(AppealStage::Withdrawn).len(), 1);
    }

    #[test]
    fn overdue_only_open() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        // deadline 2025-06-01; check after that
        assert_eq!(r.overdue("2025-06-15T00:00:00Z").len(), 1);
        // close it via Withdrawn
        r.transition(
            "a1",
            AppealStage::Withdrawn,
            "subject",
            "n",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        assert_eq!(r.overdue("2025-06-15T00:00:00Z").len(), 0);
    }

    #[test]
    fn overturned_query() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        r.file(appeal("a2")).unwrap();
        // a1 → Overturned
        r.transition(
            "a1",
            AppealStage::Verified,
            "ops",
            "ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a1",
            AppealStage::Overturned,
            "reviewer",
            "subject prevailed",
            "2025-05-15T00:00:00Z",
            Some("Reason".into()),
            Some("approve".into()),
        )
        .unwrap();
        // a2 → Upheld
        r.transition(
            "a2",
            AppealStage::Verified,
            "ops",
            "ok",
            "2025-05-03T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a2",
            AppealStage::UnderReview,
            "reviewer",
            "hearing",
            "2025-05-10T00:00:00Z",
            None,
            None,
        )
        .unwrap();
        r.transition(
            "a2",
            AppealStage::Upheld,
            "reviewer",
            "affirmed",
            "2025-05-15T00:00:00Z",
            Some("Reason".into()),
            None,
        )
        .unwrap();
        let overturned = r.overturned();
        assert_eq!(overturned.len(), 1);
        assert_eq!(overturned[0].appeal_id, "a1");
    }

    #[test]
    fn high_impact_filter() {
        let r = AppealRegister::new();
        r.file(appeal("a1")).unwrap();
        let mut other = appeal("a2");
        other.original.impact = DecisionImpact::Informational;
        r.file(other).unwrap();
        assert_eq!(r.high_impact().len(), 1);
        assert_eq!(r.high_impact()[0].appeal_id, "a1");
    }

    #[test]
    fn stage_helpers() {
        for s in [
            AppealStage::Upheld,
            AppealStage::PartiallyOverturned,
            AppealStage::Overturned,
            AppealStage::Withdrawn,
            AppealStage::VerificationFailed,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            AppealStage::Filed,
            AppealStage::Verified,
            AppealStage::EvidenceCollection,
            AppealStage::UnderReview,
        ] {
            assert!(!s.is_terminal());
        }
        assert!(AppealStage::Overturned.original_overturned());
        assert!(AppealStage::PartiallyOverturned.original_overturned());
        assert!(!AppealStage::Upheld.original_overturned());
        assert!(!AppealStage::Withdrawn.original_overturned());
    }

    #[test]
    fn count_tracks() {
        let r = AppealRegister::new();
        assert_eq!(r.count(), 0);
        r.file(appeal("a1")).unwrap();
        r.file(appeal("a2")).unwrap();
        assert_eq!(r.count(), 2);
    }

    #[test]
    fn appeal_serde() {
        let a = appeal("a1");
        let j = serde_json::to_string(&a).unwrap();
        let back: Appeal = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn original_evidence_event_serde() {
        let o = original();
        assert_eq!(
            o,
            serde_json::from_str::<OriginalDecision>(&serde_json::to_string(&o).unwrap()).unwrap()
        );
        let e = evid("e1");
        assert_eq!(
            e,
            serde_json::from_str::<EvidenceItem>(&serde_json::to_string(&e).unwrap()).unwrap()
        );
        let ev = AppealEvent {
            at: "2025-05-01T00:00:00Z".into(),
            actor: "x".into(),
            stage: AppealStage::Filed,
            note: "n".into(),
        };
        assert_eq!(
            ev,
            serde_json::from_str::<AppealEvent>(&serde_json::to_string(&ev).unwrap()).unwrap()
        );
    }

    #[test]
    fn enums_serde() {
        for s in [
            AppealStage::Filed,
            AppealStage::Verified,
            AppealStage::VerificationFailed,
            AppealStage::EvidenceCollection,
            AppealStage::UnderReview,
            AppealStage::Upheld,
            AppealStage::PartiallyOverturned,
            AppealStage::Overturned,
            AppealStage::Withdrawn,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<AppealStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for i in [
            DecisionImpact::Informational,
            DecisionImpact::Service,
            DecisionImpact::Restrictive,
            DecisionImpact::LegalOrSignificant,
        ] {
            assert_eq!(
                i,
                serde_json::from_str::<DecisionImpact>(&serde_json::to_string(&i).unwrap())
                    .unwrap()
            );
        }
    }
}
