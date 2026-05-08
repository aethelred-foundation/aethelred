//! Vendor due-diligence assessment register.
//!
//! Maps to **SOC 2 CC9.2** (vendor management), **ISO 27001 A.15.1.1**
//! (information security policy for supplier relationships), and
//! **NIST 800-53 SR-3** (supply chain controls). Each new vendor (and
//! periodic re-assessment of existing vendors) triggers a Due-Diligence
//! Questionnaire (DDQ) — security, compliance, financial, operational —
//! whose responses are scored and roll up to an overall risk rating.
//!
//! ## Scoring
//!
//! Each [`Question`] has a `weight` (1-10) and a recorded
//! `score` (0-5; 0 = no answer, 1 = unacceptable, 5 = excellent). The
//! assessment's overall `weighted_score` is `Σ(score × weight) /
//! Σ(weight)` rounded to two decimal places (returned in basis points,
//! 0-500).
//!
//! ## Lifecycle
//!
//! `Drafted → Sent → InReview → Completed | Cancelled`
//!
//! Distinct from [`crate::third_party_risk`] (running risk register) and
//! [`crate::subprocessor_register`] (the public list); this is the
//! **per-engagement assessment** that feeds into both.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AssessmentStage
// =============================================================================

/// Lifecycle stage of an assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStage {
    /// Drafted internally; not yet sent.
    Drafted,
    /// Sent to vendor; awaiting responses.
    Sent,
    /// Reviewer evaluating responses.
    InReview,
    /// Assessment closed with overall verdict.
    Completed,
    /// Cancelled before completion.
    Cancelled,
}

impl AssessmentStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

// =============================================================================
// QuestionDomain
// =============================================================================

/// Domain bucket for a question (drives section grouping).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionDomain {
    /// Information security.
    Security,
    /// Privacy / data protection.
    Privacy,
    /// Compliance / regulatory.
    Compliance,
    /// Financial health.
    Financial,
    /// Operational maturity.
    Operational,
    /// Business continuity.
    BusinessContinuity,
    /// AI / ML / model governance.
    AiMl,
    /// Other.
    Other,
}

// =============================================================================
// Verdict
// =============================================================================

/// Final risk verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Pending verdict.
    Pending,
    /// Vendor approved.
    Approved,
    /// Approved with explicit conditions / remediations.
    ApprovedWithConditions,
    /// Vendor rejected.
    Rejected,
}

impl Verdict {
    /// True if onboarding may proceed.
    pub fn permits_engagement(self) -> bool {
        matches!(self, Self::Approved | Self::ApprovedWithConditions)
    }
}

// =============================================================================
// Question
// =============================================================================

/// One question on the questionnaire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Question {
    /// Stable id within the assessment.
    pub question_id: String,
    /// Domain.
    pub domain: QuestionDomain,
    /// Display text.
    pub text: String,
    /// Weight (1-10; clamped on input).
    pub weight: u8,
    /// Score (0-5; 0 = no response, 1 = unacceptable, 5 = excellent).
    pub score: u8,
    /// Free-text vendor response.
    pub response: Option<String>,
    /// Free-text reviewer note.
    pub reviewer_note: Option<String>,
    /// Optional evidence URL / attachment reference.
    pub evidence_ref: Option<String>,
}

impl Question {
    /// New question with default weight 1, score 0.
    pub fn new(
        question_id: impl Into<String>,
        domain: QuestionDomain,
        text: impl Into<String>,
        weight: u8,
    ) -> Self {
        Self {
            question_id: question_id.into(),
            domain,
            text: text.into(),
            weight: weight.clamp(1, 10),
            score: 0,
            response: None,
            reviewer_note: None,
            evidence_ref: None,
        }
    }
}

// =============================================================================
// VendorAssessment
// =============================================================================

/// One vendor assessment instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VendorAssessment {
    /// Unique id (e.g., "VA-2025-007").
    pub assessment_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Linked vendor id ([`crate::third_party_risk`]).
    pub vendor_id: String,
    /// Display vendor name.
    pub vendor_name: String,
    /// Title / scope description.
    pub title: String,
    /// Reviewer team / individual.
    pub reviewer: String,
    /// Period label (e.g., "Q1-2025", "annual-2025").
    pub period: String,
    /// Questions.
    pub questions: Vec<Question>,
    /// Stage.
    pub stage: AssessmentStage,
    /// Verdict (only meaningful when stage is Completed).
    pub verdict: Verdict,
    /// Free-text overall recommendation.
    pub recommendation: Option<String>,
    /// RFC 3339 — drafted.
    pub drafted_at: String,
    /// RFC 3339 — sent.
    pub sent_at: Option<String>,
    /// RFC 3339 — reviewer started review.
    pub review_started_at: Option<String>,
    /// RFC 3339 — completed.
    pub completed_at: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl VendorAssessment {
    /// New `Drafted` assessment.
    pub fn new(
        assessment_id: impl Into<String>,
        tenant_id: impl Into<String>,
        vendor_id: impl Into<String>,
        vendor_name: impl Into<String>,
        title: impl Into<String>,
        reviewer: impl Into<String>,
        period: impl Into<String>,
        drafted_at: impl Into<String>,
    ) -> Self {
        Self {
            assessment_id: assessment_id.into(),
            tenant_id: tenant_id.into(),
            vendor_id: vendor_id.into(),
            vendor_name: vendor_name.into(),
            title: title.into(),
            reviewer: reviewer.into(),
            period: period.into(),
            questions: Vec::new(),
            stage: AssessmentStage::Drafted,
            verdict: Verdict::Pending,
            recommendation: None,
            drafted_at: drafted_at.into(),
            sent_at: None,
            review_started_at: None,
            completed_at: None,
            tags: Vec::new(),
        }
    }

    /// Number of questions answered (score > 0).
    pub fn answered_count(&self) -> usize {
        self.questions.iter().filter(|q| q.score > 0).count()
    }

    /// Weighted score in basis points (0-500). Returns 0 if no answered
    /// questions (sum of weights of unanswered = 0).
    pub fn weighted_score_bp(&self) -> u32 {
        let mut weighted_sum: u64 = 0;
        let mut weight_sum: u64 = 0;
        for q in &self.questions {
            if q.score == 0 {
                continue;
            }
            weighted_sum = weighted_sum
                .saturating_add(q.score as u64 * q.weight as u64 * 100);
            weight_sum = weight_sum.saturating_add(q.weight as u64);
        }
        if weight_sum == 0 {
            return 0;
        }
        (weighted_sum / weight_sum) as u32
    }

    /// Weighted score for one domain.
    pub fn domain_score_bp(&self, domain: QuestionDomain) -> u32 {
        let mut weighted_sum: u64 = 0;
        let mut weight_sum: u64 = 0;
        for q in &self.questions {
            if q.domain != domain || q.score == 0 {
                continue;
            }
            weighted_sum = weighted_sum
                .saturating_add(q.score as u64 * q.weight as u64 * 100);
            weight_sum = weight_sum.saturating_add(q.weight as u64);
        }
        if weight_sum == 0 {
            return 0;
        }
        (weighted_sum / weight_sum) as u32
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: AssessmentStage, to: AssessmentStage) -> bool {
    use AssessmentStage::*;
    matches!(
        (from, to),
        (Drafted, Sent)
            | (Drafted, Cancelled)
            | (Sent, InReview)
            | (Sent, Cancelled)
            | (InReview, Completed)
            | (InReview, Cancelled)
            | (InReview, Sent)
    )
}

// =============================================================================
// VendorAssessmentRegistry
// =============================================================================

/// Thread-safe registry of vendor assessments.
#[derive(Debug, Default)]
pub struct VendorAssessmentRegistry {
    inner: RwLock<HashMap<String, VendorAssessment>>,
}

impl VendorAssessmentRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new draft assessment.
    pub fn register(&self, assessment: VendorAssessment) -> SandboxResult<()> {
        if !matches!(assessment.stage, AssessmentStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "assessment must start Drafted, got {:?}",
                assessment.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        if g.contains_key(&assessment.assessment_id) {
            return Err(SandboxError::Other(format!(
                "assessment already registered: {}",
                assessment.assessment_id
            )));
        }
        g.insert(assessment.assessment_id.clone(), assessment);
        Ok(())
    }

    /// Add a question to a Drafted assessment.
    pub fn add_question(
        &self,
        assessment_id: &str,
        question: Question,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        if !matches!(a.stage, AssessmentStage::Drafted) {
            return Err(SandboxError::Other(format!(
                "cannot add question to {assessment_id}: stage is {:?}",
                a.stage
            )));
        }
        if a.questions
            .iter()
            .any(|q| q.question_id == question.question_id)
        {
            return Err(SandboxError::Other(format!(
                "question already present: {}",
                question.question_id
            )));
        }
        a.questions.push(question);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        assessment_id: &str,
        new_stage: AssessmentStage,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<VendorAssessment> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        if !legal_transition(a.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                a.stage, new_stage
            )));
        }
        let when = at.into();
        let _ = actor;
        a.stage = new_stage;
        match new_stage {
            AssessmentStage::Sent => a.sent_at = Some(when),
            AssessmentStage::InReview => a.review_started_at = Some(when),
            AssessmentStage::Completed | AssessmentStage::Cancelled => {
                a.completed_at = Some(when)
            }
            _ => {}
        }
        Ok(a.clone())
    }

    /// Record a vendor response on a question (must be Sent or InReview).
    pub fn record_response(
        &self,
        assessment_id: &str,
        question_id: &str,
        response: impl Into<String>,
        evidence_ref: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        if !matches!(a.stage, AssessmentStage::Sent | AssessmentStage::InReview) {
            return Err(SandboxError::Other(format!(
                "cannot record response on {assessment_id}: stage is {:?}",
                a.stage
            )));
        }
        let q = a
            .questions
            .iter_mut()
            .find(|q| q.question_id == question_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown question {question_id}")))?;
        q.response = Some(response.into());
        if let Some(e) = evidence_ref {
            q.evidence_ref = Some(e);
        }
        Ok(())
    }

    /// Score a question (1-5; 0 means clear). Must be InReview.
    pub fn score_question(
        &self,
        assessment_id: &str,
        question_id: &str,
        score: u8,
        reviewer_note: Option<String>,
    ) -> SandboxResult<()> {
        if score > 5 {
            return Err(SandboxError::Other(format!(
                "score {score} out of range (0-5)"
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        if !matches!(a.stage, AssessmentStage::InReview) {
            return Err(SandboxError::Other(format!(
                "cannot score on {assessment_id}: stage is {:?}",
                a.stage
            )));
        }
        let q = a
            .questions
            .iter_mut()
            .find(|q| q.question_id == question_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown question {question_id}")))?;
        q.score = score;
        if let Some(n) = reviewer_note {
            q.reviewer_note = Some(n);
        }
        Ok(())
    }

    /// Set the final verdict and recommendation. Must be InReview; this
    /// does NOT transition stage — call `transition(Completed, ...)`
    /// separately.
    pub fn set_verdict(
        &self,
        assessment_id: &str,
        verdict: Verdict,
        recommendation: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        if !matches!(a.stage, AssessmentStage::InReview) {
            return Err(SandboxError::Other(format!(
                "cannot set verdict on {assessment_id}: stage is {:?}",
                a.stage
            )));
        }
        a.verdict = verdict;
        if let Some(r) = recommendation {
            a.recommendation = Some(r);
        }
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, assessment_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("vendor assessment registry poisoned".into()))?;
        let a = g
            .get_mut(assessment_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown assessment {assessment_id}")))?;
        let tag = tag.into();
        if !a.tags.contains(&tag) {
            a.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, assessment_id: &str) -> Option<VendorAssessment> {
        let g = self.inner.read().ok()?;
        g.get(assessment_id).cloned()
    }

    /// All assessments.
    pub fn all(&self) -> Vec<VendorAssessment> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Assessments for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<VendorAssessment> {
        self.all()
            .into_iter()
            .filter(|a| a.tenant_id == tenant_id)
            .collect()
    }

    /// Assessments for a vendor.
    pub fn for_vendor(&self, vendor_id: &str) -> Vec<VendorAssessment> {
        self.all()
            .into_iter()
            .filter(|a| a.vendor_id == vendor_id)
            .collect()
    }

    /// Assessments at a stage.
    pub fn by_stage(&self, stage: AssessmentStage) -> Vec<VendorAssessment> {
        self.all().into_iter().filter(|a| a.stage == stage).collect()
    }

    /// Latest completed assessment for a vendor (newest completed_at).
    pub fn latest_completed_for_vendor(
        &self,
        vendor_id: &str,
    ) -> Option<VendorAssessment> {
        let mut completed: Vec<VendorAssessment> = self
            .for_vendor(vendor_id)
            .into_iter()
            .filter(|a| matches!(a.stage, AssessmentStage::Completed))
            .collect();
        completed.sort_by(|a, b| {
            a.completed_at
                .as_deref()
                .unwrap_or("")
                .cmp(b.completed_at.as_deref().unwrap_or(""))
        });
        completed.pop()
    }

    /// Number of assessments.
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

    fn assess(id: &str) -> VendorAssessment {
        VendorAssessment::new(
            id,
            "tenant-a",
            "VENDOR-007",
            "Acme Corp",
            "Annual security review",
            "compliance",
            "annual-2025",
            "2025-04-01T00:00:00Z",
        )
    }

    fn q(id: &str, domain: QuestionDomain, weight: u8) -> Question {
        Question::new(id, domain, format!("question {id}"), weight)
    }

    #[test]
    fn register_and_get() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        assert!(r.get("a1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        let err = r.register(assess("a1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_drafted() {
        let mut a = assess("a1");
        a.stage = AssessmentStage::Sent;
        let r = VendorAssessmentRegistry::new();
        let err = r.register(a).unwrap_err();
        assert!(format!("{err}").contains("must start Drafted"));
    }

    #[test]
    fn add_question_drafted_only() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        let err = r
            .add_question("a1", q("q2", QuestionDomain::Privacy, 5))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add question"));
    }

    #[test]
    fn add_question_dedupes() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        let err = r
            .add_question("a1", q("q1", QuestionDomain::Privacy, 3))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn weight_clamped_to_range() {
        let q1 = q("q1", QuestionDomain::Security, 0);
        assert_eq!(q1.weight, 1);
        let q2 = q("q2", QuestionDomain::Security, 99);
        assert_eq!(q2.weight, 10);
    }

    #[test]
    fn legal_transitions() {
        use AssessmentStage::*;
        assert!(legal_transition(Drafted, Sent));
        assert!(legal_transition(Sent, InReview));
        assert!(legal_transition(InReview, Completed));
        assert!(legal_transition(InReview, Sent));
        assert!(legal_transition(Drafted, Cancelled));
        // illegal
        assert!(!legal_transition(Drafted, InReview));
        assert!(!legal_transition(Drafted, Completed));
        assert!(!legal_transition(Completed, InReview));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        r.record_response("a1", "q1", "We use AES-256", None).unwrap();
        r.transition(
            "a1",
            AssessmentStage::InReview,
            "x",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        r.score_question("a1", "q1", 4, Some("good answer".into()))
            .unwrap();
        r.set_verdict("a1", Verdict::Approved, Some("acceptable".into()))
            .unwrap();
        let a = r
            .transition(
                "a1",
                AssessmentStage::Completed,
                "x",
                "2025-04-30T00:00:00Z",
            )
            .unwrap();
        assert_eq!(a.stage, AssessmentStage::Completed);
        assert!(a.stage.is_terminal());
        assert!(a.verdict.permits_engagement());
    }

    #[test]
    fn record_response_only_when_active() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        // Drafted → cannot record
        let err = r.record_response("a1", "q1", "x", None).unwrap_err();
        assert!(format!("{err}").contains("cannot record response"));
    }

    #[test]
    fn score_question_only_in_review() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        let err = r.score_question("a1", "q1", 4, None).unwrap_err();
        assert!(format!("{err}").contains("cannot score"));
    }

    #[test]
    fn score_out_of_range_errors() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        r.transition(
            "a1",
            AssessmentStage::InReview,
            "x",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        let err = r.score_question("a1", "q1", 6, None).unwrap_err();
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn weighted_score_basic() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 10))
            .unwrap();
        r.add_question("a1", q("q2", QuestionDomain::Privacy, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        r.transition(
            "a1",
            AssessmentStage::InReview,
            "x",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        // q1 score 5 weight 10 → 50; q2 score 3 weight 5 → 15
        // weighted_sum (×100) = (5*10 + 3*5)*100 = 6500
        // weight_sum = 15
        // weighted_score_bp = 6500/15 = 433
        r.score_question("a1", "q1", 5, None).unwrap();
        r.score_question("a1", "q2", 3, None).unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.weighted_score_bp(), 433);
    }

    #[test]
    fn weighted_score_zero_when_no_answers() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        let a = r.get("a1").unwrap();
        assert_eq!(a.weighted_score_bp(), 0);
        assert_eq!(a.answered_count(), 0);
    }

    #[test]
    fn domain_score() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("s1", QuestionDomain::Security, 1))
            .unwrap();
        r.add_question("a1", q("s2", QuestionDomain::Security, 1))
            .unwrap();
        r.add_question("a1", q("p1", QuestionDomain::Privacy, 1))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        r.transition(
            "a1",
            AssessmentStage::InReview,
            "x",
            "2025-04-15T00:00:00Z",
        )
        .unwrap();
        r.score_question("a1", "s1", 5, None).unwrap();
        r.score_question("a1", "s2", 3, None).unwrap();
        r.score_question("a1", "p1", 1, None).unwrap();
        let a = r.get("a1").unwrap();
        // security: (5*1 + 3*1)*100 / 2 = 400
        assert_eq!(a.domain_score_bp(QuestionDomain::Security), 400);
        // privacy: (1*1)*100 / 1 = 100
        assert_eq!(a.domain_score_bp(QuestionDomain::Privacy), 100);
        // financial: no questions → 0
        assert_eq!(a.domain_score_bp(QuestionDomain::Financial), 0);
    }

    #[test]
    fn verdict_permits_engagement() {
        assert!(Verdict::Approved.permits_engagement());
        assert!(Verdict::ApprovedWithConditions.permits_engagement());
        assert!(!Verdict::Rejected.permits_engagement());
        assert!(!Verdict::Pending.permits_engagement());
    }

    #[test]
    fn set_verdict_only_in_review() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        let err = r.set_verdict("a1", Verdict::Approved, None).unwrap_err();
        assert!(format!("{err}").contains("cannot set verdict"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        r.add_tag("a1", "annual").unwrap();
        r.add_tag("a1", "annual").unwrap();
        r.add_tag("a1", "high-risk").unwrap();
        assert_eq!(r.get("a1").unwrap().tags, vec!["annual", "high-risk"]);
    }

    #[test]
    fn unknown_assessment_errors() {
        let r = VendorAssessmentRegistry::new();
        let err = r
            .add_question("nope", q("q1", QuestionDomain::Security, 5))
            .unwrap_err();
        assert!(format!("{err}").contains("unknown assessment"));
    }

    #[test]
    fn for_tenant_for_vendor_filters() {
        let r = VendorAssessmentRegistry::new();
        r.register(assess("a1")).unwrap();
        let mut other = assess("a2");
        other.tenant_id = "tenant-b".into();
        other.vendor_id = "VENDOR-008".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_vendor("VENDOR-007").len(), 1);
        assert_eq!(r.for_vendor("VENDOR-008").len(), 1);
    }

    #[test]
    fn latest_completed_for_vendor() {
        let r = VendorAssessmentRegistry::new();
        // Register and complete a1 (older)
        r.register(assess("a1")).unwrap();
        r.add_question("a1", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a1", AssessmentStage::Sent, "x", "2025-01-02T00:00:00Z")
            .unwrap();
        r.transition(
            "a1",
            AssessmentStage::InReview,
            "x",
            "2025-01-10T00:00:00Z",
        )
        .unwrap();
        r.score_question("a1", "q1", 4, None).unwrap();
        r.set_verdict("a1", Verdict::Approved, None).unwrap();
        r.transition(
            "a1",
            AssessmentStage::Completed,
            "x",
            "2025-01-15T00:00:00Z",
        )
        .unwrap();
        // Register and complete a2 (newer)
        r.register(assess("a2")).unwrap();
        r.add_question("a2", q("q1", QuestionDomain::Security, 5))
            .unwrap();
        r.transition("a2", AssessmentStage::Sent, "x", "2025-04-02T00:00:00Z")
            .unwrap();
        r.transition(
            "a2",
            AssessmentStage::InReview,
            "x",
            "2025-04-10T00:00:00Z",
        )
        .unwrap();
        r.score_question("a2", "q1", 5, None).unwrap();
        r.set_verdict("a2", Verdict::Approved, None).unwrap();
        r.transition(
            "a2",
            AssessmentStage::Completed,
            "x",
            "2025-04-20T00:00:00Z",
        )
        .unwrap();
        let latest = r.latest_completed_for_vendor("VENDOR-007").unwrap();
        assert_eq!(latest.assessment_id, "a2");
    }

    #[test]
    fn count_tracks() {
        let r = VendorAssessmentRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(assess("a1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn assessment_serde() {
        let a = assess("a1");
        let j = serde_json::to_string(&a).unwrap();
        let back: VendorAssessment = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            AssessmentStage::Drafted,
            AssessmentStage::Sent,
            AssessmentStage::InReview,
            AssessmentStage::Completed,
            AssessmentStage::Cancelled,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<AssessmentStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for v in [
            Verdict::Pending,
            Verdict::Approved,
            Verdict::ApprovedWithConditions,
            Verdict::Rejected,
        ] {
            assert_eq!(
                v,
                serde_json::from_str::<Verdict>(&serde_json::to_string(&v).unwrap()).unwrap()
            );
        }
        for d in [
            QuestionDomain::Security,
            QuestionDomain::Privacy,
            QuestionDomain::Compliance,
            QuestionDomain::Financial,
            QuestionDomain::Operational,
            QuestionDomain::BusinessContinuity,
            QuestionDomain::AiMl,
            QuestionDomain::Other,
        ] {
            assert_eq!(
                d,
                serde_json::from_str::<QuestionDomain>(&serde_json::to_string(&d).unwrap())
                    .unwrap()
            );
        }
    }
}
