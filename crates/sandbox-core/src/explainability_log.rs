//! Per-decision explainability log.
//!
//! When a regulator asks "why did the AI deny this loan?" the operator must
//! produce more than the raw output. This module records, per-decision:
//!
//! - **Feature attributions** — which inputs pushed the decision in which
//!   direction and by how much (SHAP/LIME-style values).
//! - **Counterfactual** — minimal change to inputs that would flip the
//!   decision.
//! - **Reasoning trace** — chain-of-thought / intermediate predictions / rule
//!   firings.
//!
//! Each [`ExplanationRecord`] is content-addressed (its `record_hash` is
//! the canonical id). Records are typically embedded into seals via
//! `sector_extension` so the sealed event carries its own explanation.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// FeatureAttribution
// =============================================================================

/// One feature's contribution to a decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureAttribution {
    /// Feature name (e.g. `"income"`, `"credit_score"`).
    pub feature: String,
    /// Signed contribution. Convention: positive pushes toward the
    /// positive class, negative pushes against.
    pub contribution: f64,
    /// Optional human-readable feature value at decision time
    /// (e.g. `"42000"` or `"USD 42k"`). Used for explainability prose.
    pub value: Option<String>,
}

// =============================================================================
// Counterfactual
// =============================================================================

/// A minimal-change description that would flip the decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Counterfactual {
    /// Free-text statement (e.g. "If income had been $50k instead of $40k.")
    pub statement: String,
    /// Specific feature changes (feature → from → to).
    pub feature_changes: Vec<FeatureChange>,
    /// Predicted decision under the counterfactual (`true` = positive).
    pub flipped_decision: bool,
}

/// One feature change in a counterfactual.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FeatureChange {
    /// Feature name.
    pub feature: String,
    /// Original value.
    pub from: String,
    /// Counterfactual value.
    pub to: String,
}

// =============================================================================
// ReasoningStep
// =============================================================================

/// One step in a multi-step decision pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReasoningStep {
    /// Step name (e.g. `"feature_normalization"`, `"rule_eval:over_60"`).
    pub step: String,
    /// Free-text result/observation.
    pub observation: String,
    /// Optional intermediate score.
    pub score: Option<f64>,
}

// =============================================================================
// ExplanationRecord
// =============================================================================

/// Top-level explanation for one decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExplanationRecord {
    /// Unique record id.
    pub record_id: Uuid,
    /// The decision being explained.
    pub decision: String,
    /// Tenant.
    pub tenant_id: String,
    /// Model id.
    pub model_id: String,
    /// Decision class (`true` = positive).
    pub decision_positive: bool,
    /// Optional model confidence in `[0.0, 1.0]`.
    pub confidence: Option<f64>,
    /// Feature attributions (sorted by descending |contribution|).
    pub attributions: Vec<FeatureAttribution>,
    /// Counterfactual (if available).
    pub counterfactual: Option<Counterfactual>,
    /// Reasoning steps in pipeline order.
    pub reasoning: Vec<ReasoningStep>,
    /// Free-text human-readable summary.
    pub summary: String,
    /// RFC 3339 timestamp.
    pub created_at: String,
    /// Content hash (excluding `record_hash`).
    pub record_hash: Sha256Digest,
}

impl ExplanationRecord {
    /// Top-N most-influential features (by |contribution|).
    pub fn top_features(&self, n: usize) -> Vec<&FeatureAttribution> {
        let mut v: Vec<&FeatureAttribution> = self.attributions.iter().collect();
        v.sort_by(|a, b| {
            b.contribution
                .abs()
                .partial_cmp(&a.contribution.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v.into_iter().take(n).collect()
    }

    fn compute_hash(
        decision: &str,
        tenant: &str,
        model: &str,
        decision_positive: bool,
        attributions: &[FeatureAttribution],
        summary: &str,
    ) -> Sha256Digest {
        let mut input = Vec::new();
        input.extend_from_slice(decision.as_bytes());
        input.push(0);
        input.extend_from_slice(tenant.as_bytes());
        input.push(0);
        input.extend_from_slice(model.as_bytes());
        input.push(0);
        input.push(decision_positive as u8);
        for a in attributions {
            input.extend_from_slice(a.feature.as_bytes());
            input.extend_from_slice(&a.contribution.to_le_bytes());
        }
        input.extend_from_slice(summary.as_bytes());
        Hasher::sha256(&input)
    }
}

// =============================================================================
// ExplanationBuilder
// =============================================================================

/// Builder for [`ExplanationRecord`].
pub struct ExplanationBuilder {
    tenant_id: String,
    model_id: String,
    decision: String,
    decision_positive: bool,
    confidence: Option<f64>,
    attributions: Vec<FeatureAttribution>,
    counterfactual: Option<Counterfactual>,
    reasoning: Vec<ReasoningStep>,
    summary: String,
}

impl ExplanationBuilder {
    /// New builder.
    pub fn new(
        tenant_id: impl Into<String>,
        model_id: impl Into<String>,
        decision: impl Into<String>,
        decision_positive: bool,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            model_id: model_id.into(),
            decision: decision.into(),
            decision_positive,
            confidence: None,
            attributions: Vec::new(),
            counterfactual: None,
            reasoning: Vec::new(),
            summary: String::new(),
        }
    }

    /// Builder: set confidence.
    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = Some(c.clamp(0.0, 1.0));
        self
    }

    /// Builder: add feature attribution.
    pub fn attribution(mut self, a: FeatureAttribution) -> Self {
        self.attributions.push(a);
        self
    }

    /// Builder: set counterfactual.
    pub fn counterfactual(mut self, c: Counterfactual) -> Self {
        self.counterfactual = Some(c);
        self
    }

    /// Builder: add reasoning step.
    pub fn reasoning(mut self, s: ReasoningStep) -> Self {
        self.reasoning.push(s);
        self
    }

    /// Builder: summary.
    pub fn summary(mut self, s: impl Into<String>) -> Self {
        self.summary = s.into();
        self
    }

    /// Finalize.
    pub fn build(mut self) -> ExplanationRecord {
        // Sort attributions by |contribution| desc for stable output.
        self.attributions.sort_by(|a, b| {
            b.contribution
                .abs()
                .partial_cmp(&a.contribution.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let hash = ExplanationRecord::compute_hash(
            &self.decision,
            &self.tenant_id,
            &self.model_id,
            self.decision_positive,
            &self.attributions,
            &self.summary,
        );
        ExplanationRecord {
            record_id: Uuid::now_v7(),
            decision: self.decision,
            tenant_id: self.tenant_id,
            model_id: self.model_id,
            decision_positive: self.decision_positive,
            confidence: self.confidence,
            attributions: self.attributions,
            counterfactual: self.counterfactual,
            reasoning: self.reasoning,
            summary: self.summary,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            record_hash: hash,
        }
    }
}

// =============================================================================
// ExplanationLog
// =============================================================================

/// Append-only log of explanation records.
#[derive(Default)]
pub struct ExplanationLog {
    inner: RwLock<Vec<ExplanationRecord>>,
}

impl std::fmt::Debug for ExplanationLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExplanationLog")
            .field("records", &self.len())
            .finish()
    }
}

impl ExplanationLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append.
    pub fn append(&self, record: ExplanationRecord) -> SandboxResult<Uuid> {
        let id = record.record_id;
        self.inner
            .write()
            .map_err(|_| SandboxError::Other("explanation log poisoned".into()))?
            .push(record);
        Ok(id)
    }

    /// Find by id.
    pub fn find(&self, id: Uuid) -> Option<ExplanationRecord> {
        self.inner
            .read()
            .ok()?
            .iter()
            .find(|r| r.record_id == id)
            .cloned()
    }

    /// All records.
    pub fn records(&self) -> Vec<ExplanationRecord> {
        self.inner.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Number of records.
    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter by tenant.
    pub fn for_tenant(&self, tenant: &str) -> Vec<ExplanationRecord> {
        self.records()
            .into_iter()
            .filter(|r| r.tenant_id == tenant)
            .collect()
    }

    /// Filter by model.
    pub fn for_model(&self, model: &str) -> Vec<ExplanationRecord> {
        self.records()
            .into_iter()
            .filter(|r| r.model_id == model)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(f: &str, c: f64) -> FeatureAttribution {
        FeatureAttribution {
            feature: f.into(),
            contribution: c,
            value: None,
        }
    }

    #[test]
    fn builder_produces_record() {
        let r = ExplanationBuilder::new("FAB", "model-v1", "loan-app-1", true)
            .summary("approved")
            .attribution(attr("income", 0.6))
            .build();
        assert_eq!(r.decision, "loan-app-1");
        assert_eq!(r.summary, "approved");
        assert_eq!(r.attributions.len(), 1);
    }

    #[test]
    fn attributions_sorted_by_abs_contribution() {
        let r = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("a", 0.1))
            .attribution(attr("b", -0.5))
            .attribution(attr("c", 0.3))
            .build();
        assert_eq!(r.attributions[0].feature, "b");
        assert_eq!(r.attributions[1].feature, "c");
        assert_eq!(r.attributions[2].feature, "a");
    }

    #[test]
    fn top_features_returns_n() {
        let r = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("a", 0.1))
            .attribution(attr("b", -0.5))
            .attribution(attr("c", 0.3))
            .build();
        let top2 = r.top_features(2);
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].feature, "b");
    }

    #[test]
    fn confidence_clamped_to_unit() {
        let r1 = ExplanationBuilder::new("t", "m", "d", true).confidence(2.0).build();
        let r2 = ExplanationBuilder::new("t", "m", "d", true).confidence(-1.0).build();
        assert_eq!(r1.confidence, Some(1.0));
        assert_eq!(r2.confidence, Some(0.0));
    }

    #[test]
    fn record_hash_changes_with_decision() {
        let r1 = ExplanationBuilder::new("t", "m", "d", true).build();
        let r2 = ExplanationBuilder::new("t", "m", "d", false).build();
        assert_ne!(r1.record_hash, r2.record_hash);
    }

    #[test]
    fn record_hash_changes_with_attribution() {
        let r1 = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("x", 0.1))
            .build();
        let r2 = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("x", 0.2))
            .build();
        assert_ne!(r1.record_hash, r2.record_hash);
    }

    #[test]
    fn log_appends_and_finds() {
        let l = ExplanationLog::new();
        let r = ExplanationBuilder::new("t", "m", "d", true).build();
        let id = r.record_id;
        l.append(r).unwrap();
        assert!(l.find(id).is_some());
    }

    #[test]
    fn log_filters_by_tenant() {
        let l = ExplanationLog::new();
        l.append(ExplanationBuilder::new("FAB", "m", "d1", true).build())
            .unwrap();
        l.append(ExplanationBuilder::new("ENBD", "m", "d2", true).build())
            .unwrap();
        assert_eq!(l.for_tenant("FAB").len(), 1);
        assert_eq!(l.for_tenant("ENBD").len(), 1);
    }

    #[test]
    fn log_filters_by_model() {
        let l = ExplanationLog::new();
        l.append(ExplanationBuilder::new("t", "m1", "d1", true).build())
            .unwrap();
        l.append(ExplanationBuilder::new("t", "m2", "d2", true).build())
            .unwrap();
        assert_eq!(l.for_model("m1").len(), 1);
    }

    #[test]
    fn counterfactual_recorded() {
        let cf = Counterfactual {
            statement: "Higher income".into(),
            feature_changes: vec![FeatureChange {
                feature: "income".into(),
                from: "40k".into(),
                to: "60k".into(),
            }],
            flipped_decision: true,
        };
        let r = ExplanationBuilder::new("t", "m", "d", false)
            .counterfactual(cf.clone())
            .build();
        assert_eq!(r.counterfactual, Some(cf));
    }

    #[test]
    fn reasoning_steps_preserve_order() {
        let r = ExplanationBuilder::new("t", "m", "d", true)
            .reasoning(ReasoningStep {
                step: "first".into(),
                observation: "x".into(),
                score: None,
            })
            .reasoning(ReasoningStep {
                step: "second".into(),
                observation: "y".into(),
                score: Some(0.5),
            })
            .build();
        assert_eq!(r.reasoning[0].step, "first");
        assert_eq!(r.reasoning[1].step, "second");
    }

    #[test]
    fn record_serde_round_trip() {
        let r = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("a", 0.5))
            .summary("ok")
            .build();
        let j = serde_json::to_string(&r).unwrap();
        let p: ExplanationRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn empty_log_is_empty() {
        let l = ExplanationLog::new();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
    }

    #[test]
    fn log_records_returns_all() {
        let l = ExplanationLog::new();
        for i in 0..5 {
            l.append(
                ExplanationBuilder::new("t", "m", &format!("d{i}"), true).build(),
            )
            .unwrap();
        }
        assert_eq!(l.records().len(), 5);
    }

    #[test]
    fn feature_attribution_serde() {
        let a = FeatureAttribution {
            feature: "x".into(),
            contribution: 0.5,
            value: Some("v".into()),
        };
        let j = serde_json::to_string(&a).unwrap();
        let p: FeatureAttribution = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn counterfactual_serde() {
        let cf = Counterfactual {
            statement: "x".into(),
            feature_changes: vec![],
            flipped_decision: true,
        };
        let j = serde_json::to_string(&cf).unwrap();
        let p: Counterfactual = serde_json::from_str(&j).unwrap();
        assert_eq!(p, cf);
    }

    #[test]
    fn top_features_n_larger_than_attributions() {
        let r = ExplanationBuilder::new("t", "m", "d", true)
            .attribution(attr("a", 0.5))
            .build();
        assert_eq!(r.top_features(10).len(), 1);
    }

    #[test]
    fn find_unknown_returns_none() {
        let l = ExplanationLog::new();
        assert!(l.find(Uuid::now_v7()).is_none());
    }

    #[test]
    fn record_hash_includes_summary() {
        let r1 = ExplanationBuilder::new("t", "m", "d", true)
            .summary("a")
            .build();
        let r2 = ExplanationBuilder::new("t", "m", "d", true)
            .summary("b")
            .build();
        assert_ne!(r1.record_hash, r2.record_hash);
    }

    #[test]
    fn many_records_log() {
        let l = ExplanationLog::new();
        for i in 0..100 {
            l.append(
                ExplanationBuilder::new("t", "m", &format!("d{i}"), true).build(),
            )
            .unwrap();
        }
        assert_eq!(l.len(), 100);
    }
}
