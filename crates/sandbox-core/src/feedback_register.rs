//! Customer feedback register — NPS / CSAT / qualitative responses.
//!
//! Distinct from [`crate::support_ticket_register`]'s ticket-level CSAT
//! (which scores a single resolution event), this is the **standalone
//! feedback** register: scheduled NPS surveys, post-onboarding CSAT,
//! product-feature CES (Customer Effort Score), open-ended qualitative
//! responses, and structured feature requests.
//!
//! Maps to the canonical SaaS customer-success surfaces (Gainsight /
//! Catalyst / Vitally) and Net Promoter Score / CSAT industry norms.
//!
//! ## Two views
//!
//! - **[`FeedbackResponse`]** — one survey response or unsolicited
//!   feedback item, immutable after recording.
//! - **Aggregates** — `nps_score()`, `mean_csat()`, `mean_ces()`
//!   computed across the register filtered by tenant / period / segment.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// FeedbackKind
// =============================================================================

/// Kind of feedback signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackKind {
    /// Net Promoter Score (0-10, "how likely to recommend").
    Nps,
    /// Customer Satisfaction (1-5, post-event).
    Csat,
    /// Customer Effort Score (1-7, lower is better — "how easy was it").
    Ces,
    /// Open-ended free-text feedback.
    Qualitative,
    /// Structured feature request.
    FeatureRequest,
    /// Bug report (informational; for tracking, file a ticket).
    BugReport,
    /// Churn-risk signal.
    ChurnRisk,
}

impl FeedbackKind {
    /// True if this kind has a numeric `score` value.
    pub fn is_numeric(self) -> bool {
        matches!(self, Self::Nps | Self::Csat | Self::Ces)
    }
}

// =============================================================================
// NpsSegment
// =============================================================================

/// NPS classification (Promoter / Passive / Detractor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpsSegment {
    /// Score 9-10.
    Promoter,
    /// Score 7-8.
    Passive,
    /// Score 0-6.
    Detractor,
}

impl NpsSegment {
    /// Classify a 0-10 NPS score.
    pub fn from_score(score: u8) -> Option<Self> {
        match score {
            0..=6 => Some(Self::Detractor),
            7..=8 => Some(Self::Passive),
            9..=10 => Some(Self::Promoter),
            _ => None,
        }
    }
}

// =============================================================================
// FeedbackChannel
// =============================================================================

/// Where the feedback came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackChannel {
    /// In-app survey widget.
    InAppSurvey,
    /// Email survey.
    EmailSurvey,
    /// Post-call (CSM / support) survey.
    PostCallSurvey,
    /// Onboarding milestone survey.
    OnboardingSurvey,
    /// Public feedback form.
    PublicForm,
    /// Sales / CSM call notes.
    CallNotes,
    /// Other.
    Other,
}

// =============================================================================
// FeedbackResponse
// =============================================================================

/// One feedback response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeedbackResponse {
    /// Unique id.
    pub response_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Customer id.
    pub customer_id: String,
    /// Optional surveyed user id (if multi-user customer).
    pub user_id: Option<String>,
    /// Kind.
    pub kind: FeedbackKind,
    /// Channel.
    pub channel: FeedbackChannel,
    /// Numeric score (interpretation per kind).
    pub score: Option<u8>,
    /// Free-text body.
    pub body: Option<String>,
    /// Period label (used for cohort aggregation).
    pub period: String,
    /// Customer segment / cohort label.
    pub segment: Option<String>,
    /// Whether the customer agreed to be contacted for follow-up.
    pub follow_up_consent: bool,
    /// Linked ticket id, if escalated.
    pub linked_ticket_id: Option<String>,
    /// RFC 3339 — captured.
    pub captured_at: String,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl FeedbackResponse {
    /// New numeric response.
    pub fn new_numeric(
        response_id: impl Into<String>,
        tenant_id: impl Into<String>,
        customer_id: impl Into<String>,
        kind: FeedbackKind,
        channel: FeedbackChannel,
        score: u8,
        period: impl Into<String>,
        captured_at: impl Into<String>,
    ) -> SandboxResult<Self> {
        if !kind.is_numeric() {
            return Err(SandboxError::Other(format!(
                "kind {:?} is not numeric",
                kind
            )));
        }
        let max = match kind {
            FeedbackKind::Nps => 10,
            FeedbackKind::Csat => 5,
            FeedbackKind::Ces => 7,
            _ => unreachable!(),
        };
        if score > max {
            return Err(SandboxError::Other(format!(
                "score {score} out of range for {:?} (0..={max})",
                kind
            )));
        }
        Ok(Self {
            response_id: response_id.into(),
            tenant_id: tenant_id.into(),
            customer_id: customer_id.into(),
            user_id: None,
            kind,
            channel,
            score: Some(score),
            body: None,
            period: period.into(),
            segment: None,
            follow_up_consent: false,
            linked_ticket_id: None,
            captured_at: captured_at.into(),
            tags: Vec::new(),
        })
    }

    /// New qualitative / non-numeric response.
    pub fn new_qualitative(
        response_id: impl Into<String>,
        tenant_id: impl Into<String>,
        customer_id: impl Into<String>,
        kind: FeedbackKind,
        channel: FeedbackChannel,
        body: impl Into<String>,
        period: impl Into<String>,
        captured_at: impl Into<String>,
    ) -> SandboxResult<Self> {
        if kind.is_numeric() {
            return Err(SandboxError::Other(format!(
                "kind {:?} is numeric; use new_numeric()",
                kind
            )));
        }
        Ok(Self {
            response_id: response_id.into(),
            tenant_id: tenant_id.into(),
            customer_id: customer_id.into(),
            user_id: None,
            kind,
            channel,
            score: None,
            body: Some(body.into()),
            period: period.into(),
            segment: None,
            follow_up_consent: false,
            linked_ticket_id: None,
            captured_at: captured_at.into(),
            tags: Vec::new(),
        })
    }

    /// NPS classification, if this is an NPS response.
    pub fn nps_segment(&self) -> Option<NpsSegment> {
        if !matches!(self.kind, FeedbackKind::Nps) {
            return None;
        }
        self.score.and_then(NpsSegment::from_score)
    }
}

// =============================================================================
// FeedbackRegister
// =============================================================================

/// Thread-safe register of customer feedback responses.
#[derive(Debug, Default)]
pub struct FeedbackRegister {
    inner: RwLock<HashMap<String, FeedbackResponse>>,
}

impl FeedbackRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a response.
    pub fn record(&self, response: FeedbackResponse) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("feedback register poisoned".into()))?;
        if g.contains_key(&response.response_id) {
            return Err(SandboxError::Other(format!(
                "response already recorded: {}",
                response.response_id
            )));
        }
        g.insert(response.response_id.clone(), response);
        Ok(())
    }

    /// Set segment.
    pub fn set_segment(
        &self,
        response_id: &str,
        segment: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("feedback register poisoned".into()))?;
        let r = g
            .get_mut(response_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown response {response_id}")))?;
        r.segment = Some(segment.into());
        Ok(())
    }

    /// Set follow-up consent.
    pub fn set_follow_up_consent(
        &self,
        response_id: &str,
        consent: bool,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("feedback register poisoned".into()))?;
        let r = g
            .get_mut(response_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown response {response_id}")))?;
        r.follow_up_consent = consent;
        Ok(())
    }

    /// Link a ticket id.
    pub fn link_ticket(
        &self,
        response_id: &str,
        ticket_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("feedback register poisoned".into()))?;
        let r = g
            .get_mut(response_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown response {response_id}")))?;
        r.linked_ticket_id = Some(ticket_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, response_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("feedback register poisoned".into()))?;
        let r = g
            .get_mut(response_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown response {response_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, response_id: &str) -> Option<FeedbackResponse> {
        let g = self.inner.read().ok()?;
        g.get(response_id).cloned()
    }

    /// All responses.
    pub fn all(&self) -> Vec<FeedbackResponse> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Responses for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<FeedbackResponse> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Responses for a customer.
    pub fn for_customer(&self, customer_id: &str) -> Vec<FeedbackResponse> {
        self.all()
            .into_iter()
            .filter(|r| r.customer_id == customer_id)
            .collect()
    }

    /// Responses for a period.
    pub fn for_period(&self, period: &str) -> Vec<FeedbackResponse> {
        self.all()
            .into_iter()
            .filter(|r| r.period == period)
            .collect()
    }

    /// Responses by kind.
    pub fn by_kind(&self, kind: FeedbackKind) -> Vec<FeedbackResponse> {
        self.all().into_iter().filter(|r| r.kind == kind).collect()
    }

    /// NPS score over a filtered set: `(promoters% - detractors%)`,
    /// returned in basis points (1 NPS point = 100 bp). `None` if no NPS
    /// responses exist in the filter.
    fn nps_from(responses: &[FeedbackResponse]) -> Option<i64> {
        let nps_only: Vec<NpsSegment> = responses
            .iter()
            .filter(|r| matches!(r.kind, FeedbackKind::Nps))
            .filter_map(|r| r.nps_segment())
            .collect();
        if nps_only.is_empty() {
            return None;
        }
        let total = nps_only.len() as i64;
        let promoters = nps_only
            .iter()
            .filter(|s| matches!(s, NpsSegment::Promoter))
            .count() as i64;
        let detractors = nps_only
            .iter()
            .filter(|s| matches!(s, NpsSegment::Detractor))
            .count() as i64;
        // NPS expressed as (% promoters - % detractors); use basis points
        // to avoid floats.
        Some(((promoters - detractors) * 10_000) / total)
    }

    /// NPS for the entire register.
    pub fn nps_basis_points(&self) -> Option<i64> {
        Self::nps_from(&self.all())
    }

    /// NPS for a tenant.
    pub fn nps_basis_points_for_tenant(&self, tenant_id: &str) -> Option<i64> {
        Self::nps_from(&self.for_tenant(tenant_id))
    }

    /// NPS for a period.
    pub fn nps_basis_points_for_period(&self, period: &str) -> Option<i64> {
        Self::nps_from(&self.for_period(period))
    }

    /// Mean CSAT score (1-5) over filtered responses, or `None` if empty.
    fn mean_csat_from(responses: &[FeedbackResponse]) -> Option<f64> {
        let scores: Vec<u8> = responses
            .iter()
            .filter(|r| matches!(r.kind, FeedbackKind::Csat))
            .filter_map(|r| r.score)
            .collect();
        if scores.is_empty() {
            return None;
        }
        let sum: u32 = scores.iter().map(|s| *s as u32).sum();
        Some(sum as f64 / scores.len() as f64)
    }

    /// Overall mean CSAT.
    pub fn mean_csat(&self) -> Option<f64> {
        Self::mean_csat_from(&self.all())
    }

    /// Mean CSAT for a tenant.
    pub fn mean_csat_for_tenant(&self, tenant_id: &str) -> Option<f64> {
        Self::mean_csat_from(&self.for_tenant(tenant_id))
    }

    /// Mean CES (lower better) over filtered responses.
    fn mean_ces_from(responses: &[FeedbackResponse]) -> Option<f64> {
        let scores: Vec<u8> = responses
            .iter()
            .filter(|r| matches!(r.kind, FeedbackKind::Ces))
            .filter_map(|r| r.score)
            .collect();
        if scores.is_empty() {
            return None;
        }
        let sum: u32 = scores.iter().map(|s| *s as u32).sum();
        Some(sum as f64 / scores.len() as f64)
    }

    /// Mean CES.
    pub fn mean_ces(&self) -> Option<f64> {
        Self::mean_ces_from(&self.all())
    }

    /// Number of recorded responses.
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

    fn nps(id: &str, score: u8) -> FeedbackResponse {
        FeedbackResponse::new_numeric(
            id,
            "tenant-a",
            "customer-1",
            FeedbackKind::Nps,
            FeedbackChannel::InAppSurvey,
            score,
            "Q1-2025",
            "2025-04-01T00:00:00Z",
        )
        .unwrap()
    }

    fn csat(id: &str, score: u8) -> FeedbackResponse {
        FeedbackResponse::new_numeric(
            id,
            "tenant-a",
            "customer-1",
            FeedbackKind::Csat,
            FeedbackChannel::PostCallSurvey,
            score,
            "Q1-2025",
            "2025-04-01T00:00:00Z",
        )
        .unwrap()
    }

    fn ces(id: &str, score: u8) -> FeedbackResponse {
        FeedbackResponse::new_numeric(
            id,
            "tenant-a",
            "customer-1",
            FeedbackKind::Ces,
            FeedbackChannel::EmailSurvey,
            score,
            "Q1-2025",
            "2025-04-01T00:00:00Z",
        )
        .unwrap()
    }

    fn qual(id: &str) -> FeedbackResponse {
        FeedbackResponse::new_qualitative(
            id,
            "tenant-a",
            "customer-1",
            FeedbackKind::Qualitative,
            FeedbackChannel::PublicForm,
            "Body of qualitative response",
            "Q1-2025",
            "2025-04-01T00:00:00Z",
        )
        .unwrap()
    }

    #[test]
    fn nps_score_range() {
        assert!(FeedbackResponse::new_numeric(
            "x",
            "t",
            "c",
            FeedbackKind::Nps,
            FeedbackChannel::InAppSurvey,
            10,
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .is_ok());
        let err = FeedbackResponse::new_numeric(
            "x",
            "t",
            "c",
            FeedbackKind::Nps,
            FeedbackChannel::InAppSurvey,
            11,
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn csat_score_range() {
        let err = FeedbackResponse::new_numeric(
            "x",
            "t",
            "c",
            FeedbackKind::Csat,
            FeedbackChannel::InAppSurvey,
            6,
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn ces_score_range() {
        let err = FeedbackResponse::new_numeric(
            "x",
            "t",
            "c",
            FeedbackKind::Ces,
            FeedbackChannel::InAppSurvey,
            8,
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("out of range"));
    }

    #[test]
    fn qualitative_constructor_rejects_numeric_kind() {
        let err = FeedbackResponse::new_qualitative(
            "x",
            "t",
            "c",
            FeedbackKind::Nps,
            FeedbackChannel::PublicForm,
            "body",
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("is numeric"));
    }

    #[test]
    fn numeric_constructor_rejects_non_numeric_kind() {
        let err = FeedbackResponse::new_numeric(
            "x",
            "t",
            "c",
            FeedbackKind::Qualitative,
            FeedbackChannel::PublicForm,
            5,
            "Q1",
            "2025-04-01T00:00:00Z",
        )
        .unwrap_err();
        assert!(format!("{err}").contains("not numeric"));
    }

    #[test]
    fn nps_segment_classification() {
        assert_eq!(NpsSegment::from_score(10), Some(NpsSegment::Promoter));
        assert_eq!(NpsSegment::from_score(9), Some(NpsSegment::Promoter));
        assert_eq!(NpsSegment::from_score(8), Some(NpsSegment::Passive));
        assert_eq!(NpsSegment::from_score(7), Some(NpsSegment::Passive));
        assert_eq!(NpsSegment::from_score(6), Some(NpsSegment::Detractor));
        assert_eq!(NpsSegment::from_score(0), Some(NpsSegment::Detractor));
        assert_eq!(NpsSegment::from_score(11), None);
    }

    #[test]
    fn nps_segment_method() {
        assert_eq!(nps("a", 9).nps_segment(), Some(NpsSegment::Promoter));
        assert_eq!(nps("a", 5).nps_segment(), Some(NpsSegment::Detractor));
        // Not NPS → None
        assert_eq!(csat("a", 5).nps_segment(), None);
    }

    #[test]
    fn record_and_get() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 9)).unwrap();
        assert!(r.get("a").is_some());
    }

    #[test]
    fn duplicate_record_errors() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 9)).unwrap();
        let err = r.record(nps("a", 10)).unwrap_err();
        assert!(format!("{err}").contains("already recorded"));
    }

    #[test]
    fn set_segment_consent_link_tag() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 9)).unwrap();
        r.set_segment("a", "enterprise").unwrap();
        r.set_follow_up_consent("a", true).unwrap();
        r.link_ticket("a", "TICK-007").unwrap();
        r.add_tag("a", "champion").unwrap();
        r.add_tag("a", "champion").unwrap();
        let f = r.get("a").unwrap();
        assert_eq!(f.segment.as_deref(), Some("enterprise"));
        assert!(f.follow_up_consent);
        assert_eq!(f.linked_ticket_id.as_deref(), Some("TICK-007"));
        assert_eq!(f.tags, vec!["champion"]);
    }

    #[test]
    fn unknown_response_errors() {
        let r = FeedbackRegister::new();
        let err = r.set_segment("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown response"));
    }

    #[test]
    fn nps_basis_points_calculation() {
        let r = FeedbackRegister::new();
        // 5 promoters, 1 passive, 4 detractors → NPS = (5-4)/10*100 = +10
        // Basis points = +1000
        for i in 0..5 {
            r.record(nps(&format!("p{i}"), 10)).unwrap();
        }
        r.record(nps("pa1", 7)).unwrap();
        for i in 0..4 {
            r.record(nps(&format!("d{i}"), 3)).unwrap();
        }
        assert_eq!(r.nps_basis_points(), Some(1000));
    }

    #[test]
    fn nps_basis_points_excludes_non_nps() {
        let r = FeedbackRegister::new();
        r.record(nps("p", 10)).unwrap();
        r.record(csat("c", 5)).unwrap(); // ignored
        assert_eq!(r.nps_basis_points(), Some(10000)); // 100% promoter
    }

    #[test]
    fn nps_basis_points_no_responses() {
        let r = FeedbackRegister::new();
        r.record(csat("c", 5)).unwrap();
        assert_eq!(r.nps_basis_points(), None);
    }

    #[test]
    fn nps_for_tenant_filters() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 10)).unwrap();
        let mut other = nps("b", 0);
        other.tenant_id = "tenant-b".into();
        r.record(other).unwrap();
        assert_eq!(r.nps_basis_points_for_tenant("tenant-a"), Some(10000));
        assert_eq!(r.nps_basis_points_for_tenant("tenant-b"), Some(-10000));
    }

    #[test]
    fn nps_for_period_filters() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 10)).unwrap();
        let mut q2 = nps("b", 0);
        q2.period = "Q2-2025".into();
        r.record(q2).unwrap();
        assert_eq!(r.nps_basis_points_for_period("Q1-2025"), Some(10000));
        assert_eq!(r.nps_basis_points_for_period("Q2-2025"), Some(-10000));
    }

    #[test]
    fn mean_csat_calculation() {
        let r = FeedbackRegister::new();
        r.record(csat("a", 5)).unwrap();
        r.record(csat("b", 4)).unwrap();
        r.record(csat("c", 3)).unwrap();
        // Add unrelated NPS — should be excluded
        r.record(nps("nps", 10)).unwrap();
        let m = r.mean_csat().unwrap();
        assert!((m - 4.0).abs() < 1e-9);
    }

    #[test]
    fn mean_ces_calculation() {
        let r = FeedbackRegister::new();
        r.record(ces("a", 2)).unwrap();
        r.record(ces("b", 4)).unwrap();
        let m = r.mean_ces().unwrap();
        assert!((m - 3.0).abs() < 1e-9);
    }

    #[test]
    fn mean_csat_none_when_no_csat() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 10)).unwrap();
        assert!(r.mean_csat().is_none());
    }

    #[test]
    fn mean_csat_for_tenant_filters() {
        let r = FeedbackRegister::new();
        r.record(csat("a", 5)).unwrap();
        let mut other = csat("b", 1);
        other.tenant_id = "tenant-b".into();
        r.record(other).unwrap();
        assert!((r.mean_csat_for_tenant("tenant-a").unwrap() - 5.0).abs() < 1e-9);
        assert!((r.mean_csat_for_tenant("tenant-b").unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn for_filters() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 10)).unwrap();
        let mut other = nps("b", 5);
        other.tenant_id = "tenant-b".into();
        other.customer_id = "customer-2".into();
        other.period = "Q2-2025".into();
        r.record(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_customer("customer-1").len(), 1);
        assert_eq!(r.for_customer("customer-2").len(), 1);
        assert_eq!(r.for_period("Q1-2025").len(), 1);
        assert_eq!(r.for_period("Q2-2025").len(), 1);
    }

    #[test]
    fn by_kind_filter() {
        let r = FeedbackRegister::new();
        r.record(nps("a", 10)).unwrap();
        r.record(csat("b", 5)).unwrap();
        r.record(qual("c")).unwrap();
        assert_eq!(r.by_kind(FeedbackKind::Nps).len(), 1);
        assert_eq!(r.by_kind(FeedbackKind::Csat).len(), 1);
        assert_eq!(r.by_kind(FeedbackKind::Qualitative).len(), 1);
        assert_eq!(r.by_kind(FeedbackKind::ChurnRisk).len(), 0);
    }

    #[test]
    fn kind_helpers() {
        assert!(FeedbackKind::Nps.is_numeric());
        assert!(FeedbackKind::Csat.is_numeric());
        assert!(FeedbackKind::Ces.is_numeric());
        assert!(!FeedbackKind::Qualitative.is_numeric());
        assert!(!FeedbackKind::FeatureRequest.is_numeric());
    }

    #[test]
    fn count_tracks() {
        let r = FeedbackRegister::new();
        assert_eq!(r.count(), 0);
        r.record(nps("a", 9)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn response_serde() {
        let n = nps("a", 9);
        let j = serde_json::to_string(&n).unwrap();
        let back: FeedbackResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn enums_serde() {
        for k in [
            FeedbackKind::Nps,
            FeedbackKind::Csat,
            FeedbackKind::Ces,
            FeedbackKind::Qualitative,
            FeedbackKind::FeatureRequest,
            FeedbackKind::BugReport,
            FeedbackKind::ChurnRisk,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<FeedbackKind>(&serde_json::to_string(&k).unwrap()).unwrap()
            );
        }
        for s in [NpsSegment::Promoter, NpsSegment::Passive, NpsSegment::Detractor] {
            assert_eq!(
                s,
                serde_json::from_str::<NpsSegment>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for c in [
            FeedbackChannel::InAppSurvey,
            FeedbackChannel::EmailSurvey,
            FeedbackChannel::PostCallSurvey,
            FeedbackChannel::OnboardingSurvey,
            FeedbackChannel::PublicForm,
            FeedbackChannel::CallNotes,
            FeedbackChannel::Other,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<FeedbackChannel>(&serde_json::to_string(&c).unwrap())
                    .unwrap()
            );
        }
    }
}
