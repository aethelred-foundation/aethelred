//! Sampled inference-audit log.
//!
//! Production model traffic is too high to log every inference. This
//! module provides a **deterministic sampling buffer** that captures a
//! representative slice of inferences for offline review by ML safety
//! and quality teams. Each captured record stores the full request/
//! response shape (without raw PII payload — pointers / hashes only),
//! the model id/version, latency, and any reviewer verdicts.
//!
//! Maps to NIST AI RMF MEASURE-2.7 (continuous monitoring) and EU AI Act
//! Art 12 (logging requirements). Distinct from
//! [`crate::explainability_log`] (which captures *why* one decision was
//! made) and [`crate::tool_invocation`] (which logs *agent* actions);
//! this is the **batch sampling layer** for review of routine inferences.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// SamplingPolicy
// =============================================================================

/// Sampling policy for inference capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingPolicy {
    /// Capture every Nth request (e.g., N=1000).
    Periodic,
    /// Capture all requests where the model output's confidence is below
    /// a threshold — surfaces low-confidence cases for review.
    LowConfidence,
    /// Capture all requests flagged by the runtime (e.g., adversarial
    /// detector).
    FlaggedOnly,
    /// Capture everything (full firehose — only for development).
    All,
}

// =============================================================================
// ReviewVerdict
// =============================================================================

/// Reviewer verdict on a captured inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// Output looked correct.
    Correct,
    /// Output looked correct but borderline.
    Borderline,
    /// Output was wrong.
    Incorrect,
    /// Output was unsafe / violated policy.
    Unsafe,
    /// Could not determine — needs more context.
    Inconclusive,
}

impl ReviewVerdict {
    /// True if the verdict represents a quality regression.
    pub fn is_regression(self) -> bool {
        matches!(self, Self::Incorrect | Self::Unsafe)
    }
}

// =============================================================================
// CapturedInference
// =============================================================================

/// One captured inference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapturedInference {
    /// Unique id (e.g., trace id).
    pub inference_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Model id.
    pub model_id: String,
    /// Model version.
    pub model_version: String,
    /// SHA-256 hex of the request payload (PII-safe pointer).
    pub request_hash: String,
    /// SHA-256 hex of the response payload.
    pub response_hash: String,
    /// Optional confidence / score reported by the model.
    pub confidence: Option<f64>,
    /// Latency in milliseconds.
    pub latency_ms: u64,
    /// Why this inference was captured.
    pub policy: SamplingPolicy,
    /// RFC 3339 — when the inference ran.
    pub captured_at: String,
    /// Reviewer username, if reviewed.
    pub reviewer: Option<String>,
    /// Reviewer verdict, if reviewed.
    pub verdict: Option<ReviewVerdict>,
    /// RFC 3339 — when reviewed.
    pub reviewed_at: Option<String>,
    /// Free-text reviewer note.
    pub reviewer_note: Option<String>,
    /// Free-form tags ("adversarial", "edge-case").
    pub tags: Vec<String>,
}

impl CapturedInference {
    /// True if this record has been reviewed.
    pub fn is_reviewed(&self) -> bool {
        self.verdict.is_some()
    }
}

// =============================================================================
// InferenceAuditLog
// =============================================================================

/// Capacity-bounded sampling log of inferences.
///
/// When `capacity` is reached, oldest entries are evicted FIFO.
#[derive(Debug)]
pub struct InferenceAuditLog {
    inner: RwLock<HashMap<String, CapturedInference>>, // index by inference_id
    order: RwLock<Vec<String>>,                        // FIFO order for eviction
    capacity: usize,
}

impl InferenceAuditLog {
    /// New log with `capacity` records.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            order: RwLock::new(Vec::new()),
            capacity,
        }
    }

    /// Default capacity-10000 log.
    pub fn default_capacity() -> Self {
        Self::new(10_000)
    }

    /// Capture an inference. If `inference_id` already exists, the entry
    /// is replaced (idempotent). When at capacity, oldest is evicted.
    pub fn capture(&self, record: CapturedInference) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("inference audit log poisoned".into()))?;
        let mut o = self
            .order
            .write()
            .map_err(|_| SandboxError::Other("inference audit log poisoned".into()))?;
        if g.contains_key(&record.inference_id) {
            // Replace in-place; preserve position.
            g.insert(record.inference_id.clone(), record);
            return Ok(());
        }
        // FIFO eviction.
        while g.len() >= self.capacity && !o.is_empty() {
            let evict = o.remove(0);
            g.remove(&evict);
        }
        if self.capacity == 0 {
            // Pathological zero-capacity → don't keep anything.
            return Ok(());
        }
        o.push(record.inference_id.clone());
        g.insert(record.inference_id.clone(), record);
        Ok(())
    }

    /// Apply a reviewer verdict.
    pub fn record_review(
        &self,
        inference_id: &str,
        reviewer: impl Into<String>,
        verdict: ReviewVerdict,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<CapturedInference> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("inference audit log poisoned".into()))?;
        let r = g
            .get_mut(inference_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown inference {inference_id}")))?;
        r.reviewer = Some(reviewer.into());
        r.verdict = Some(verdict);
        r.reviewed_at = Some(at.into());
        if let Some(n) = note {
            r.reviewer_note = Some(n);
        }
        Ok(r.clone())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, inference_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("inference audit log poisoned".into()))?;
        let r = g
            .get_mut(inference_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown inference {inference_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, inference_id: &str) -> Option<CapturedInference> {
        let g = self.inner.read().ok()?;
        g.get(inference_id).cloned()
    }

    /// All captured records.
    pub fn all(&self) -> Vec<CapturedInference> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Records for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<CapturedInference> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Records for a model.
    pub fn for_model(&self, model_id: &str) -> Vec<CapturedInference> {
        self.all()
            .into_iter()
            .filter(|r| r.model_id == model_id)
            .collect()
    }

    /// Records captured under a specific sampling policy.
    pub fn by_policy(&self, policy: SamplingPolicy) -> Vec<CapturedInference> {
        self.all().into_iter().filter(|r| r.policy == policy).collect()
    }

    /// Records that have not yet been reviewed.
    pub fn unreviewed(&self) -> Vec<CapturedInference> {
        self.all().into_iter().filter(|r| !r.is_reviewed()).collect()
    }

    /// Records whose review verdict is a regression.
    pub fn regressions(&self) -> Vec<CapturedInference> {
        self.all()
            .into_iter()
            .filter(|r| r.verdict.map(|v| v.is_regression()).unwrap_or(false))
            .collect()
    }

    /// Number of captured records.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, policy: SamplingPolicy) -> CapturedInference {
        CapturedInference {
            inference_id: id.into(),
            tenant_id: "tenant-a".into(),
            model_id: "fraud-scorer".into(),
            model_version: "v3".into(),
            request_hash: "abcd".into(),
            response_hash: "efgh".into(),
            confidence: Some(0.85),
            latency_ms: 42,
            policy,
            captured_at: "2025-05-01T00:00:00Z".into(),
            reviewer: None,
            verdict: None,
            reviewed_at: None,
            reviewer_note: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn capture_and_get() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        let r = log.get("i1").unwrap();
        assert_eq!(r.policy, SamplingPolicy::Periodic);
        assert!(!r.is_reviewed());
    }

    #[test]
    fn capacity_evicts_oldest() {
        let log = InferenceAuditLog::new(3);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i2", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i3", SamplingPolicy::Periodic)).unwrap();
        assert_eq!(log.count(), 3);
        log.capture(rec("i4", SamplingPolicy::Periodic)).unwrap();
        assert_eq!(log.count(), 3);
        // i1 evicted, i4 present
        assert!(log.get("i1").is_none());
        assert!(log.get("i4").is_some());
    }

    #[test]
    fn capture_replaces_existing_id() {
        let log = InferenceAuditLog::new(3);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        let mut updated = rec("i1", SamplingPolicy::FlaggedOnly);
        updated.latency_ms = 999;
        log.capture(updated).unwrap();
        let r = log.get("i1").unwrap();
        assert_eq!(r.policy, SamplingPolicy::FlaggedOnly);
        assert_eq!(r.latency_ms, 999);
    }

    #[test]
    fn zero_capacity_drops_everything() {
        let log = InferenceAuditLog::new(0);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn record_review_sets_verdict() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.record_review(
            "i1",
            "carol",
            ReviewVerdict::Correct,
            "2025-05-02T00:00:00Z",
            None,
        )
        .unwrap();
        let r = log.get("i1").unwrap();
        assert_eq!(r.verdict, Some(ReviewVerdict::Correct));
        assert_eq!(r.reviewer.as_deref(), Some("carol"));
        assert!(r.is_reviewed());
    }

    #[test]
    fn record_review_unknown_errors() {
        let log = InferenceAuditLog::new(10);
        let err = log
            .record_review(
                "x",
                "carol",
                ReviewVerdict::Correct,
                "2025-05-02T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown inference"));
    }

    #[test]
    fn add_tag_dedupes() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.add_tag("i1", "edge-case").unwrap();
        log.add_tag("i1", "edge-case").unwrap();
        log.add_tag("i1", "fraud").unwrap();
        assert_eq!(log.get("i1").unwrap().tags, vec!["edge-case", "fraud"]);
    }

    #[test]
    fn unreviewed_filter() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i2", SamplingPolicy::Periodic)).unwrap();
        log.record_review(
            "i1",
            "carol",
            ReviewVerdict::Correct,
            "2025-05-02T00:00:00Z",
            None,
        )
        .unwrap();
        let un = log.unreviewed();
        let ids: Vec<_> = un.iter().map(|r| r.inference_id.clone()).collect();
        assert_eq!(ids, vec!["i2"]);
    }

    #[test]
    fn regressions_filter() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i2", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i3", SamplingPolicy::Periodic)).unwrap();
        log.record_review(
            "i1",
            "carol",
            ReviewVerdict::Correct,
            "2025-05-02T00:00:00Z",
            None,
        )
        .unwrap();
        log.record_review(
            "i2",
            "carol",
            ReviewVerdict::Incorrect,
            "2025-05-02T00:00:00Z",
            None,
        )
        .unwrap();
        log.record_review(
            "i3",
            "carol",
            ReviewVerdict::Unsafe,
            "2025-05-02T00:00:00Z",
            None,
        )
        .unwrap();
        let regs = log.regressions();
        let ids: Vec<_> = regs.iter().map(|r| r.inference_id.clone()).collect();
        assert!(ids.contains(&"i2".to_string()));
        assert!(ids.contains(&"i3".to_string()));
        assert!(!ids.contains(&"i1".to_string()));
    }

    #[test]
    fn for_tenant_for_model_filters() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        let mut other = rec("i2", SamplingPolicy::Periodic);
        other.tenant_id = "tenant-b".into();
        other.model_id = "scoring-other".into();
        log.capture(other).unwrap();
        assert_eq!(log.for_tenant("tenant-a").len(), 1);
        assert_eq!(log.for_tenant("tenant-b").len(), 1);
        assert_eq!(log.for_model("fraud-scorer").len(), 1);
        assert_eq!(log.for_model("scoring-other").len(), 1);
    }

    #[test]
    fn by_policy_filters() {
        let log = InferenceAuditLog::new(10);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        log.capture(rec("i2", SamplingPolicy::LowConfidence)).unwrap();
        log.capture(rec("i3", SamplingPolicy::FlaggedOnly)).unwrap();
        assert_eq!(log.by_policy(SamplingPolicy::Periodic).len(), 1);
        assert_eq!(log.by_policy(SamplingPolicy::LowConfidence).len(), 1);
        assert_eq!(log.by_policy(SamplingPolicy::FlaggedOnly).len(), 1);
        assert_eq!(log.by_policy(SamplingPolicy::All).len(), 0);
    }

    #[test]
    fn verdict_regression_helpers() {
        assert!(ReviewVerdict::Incorrect.is_regression());
        assert!(ReviewVerdict::Unsafe.is_regression());
        assert!(!ReviewVerdict::Correct.is_regression());
        assert!(!ReviewVerdict::Borderline.is_regression());
        assert!(!ReviewVerdict::Inconclusive.is_regression());
    }

    #[test]
    fn count_and_capacity() {
        let log = InferenceAuditLog::new(7);
        assert_eq!(log.capacity(), 7);
        assert_eq!(log.count(), 0);
        log.capture(rec("i1", SamplingPolicy::Periodic)).unwrap();
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn default_capacity_is_10000() {
        let log = InferenceAuditLog::default_capacity();
        assert_eq!(log.capacity(), 10_000);
    }

    #[test]
    fn captured_serde() {
        let r = rec("i1", SamplingPolicy::Periodic);
        let j = serde_json::to_string(&r).unwrap();
        let back: CapturedInference = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enums_serde() {
        for p in [
            SamplingPolicy::Periodic,
            SamplingPolicy::LowConfidence,
            SamplingPolicy::FlaggedOnly,
            SamplingPolicy::All,
        ] {
            assert_eq!(
                p,
                serde_json::from_str::<SamplingPolicy>(&serde_json::to_string(&p).unwrap())
                    .unwrap()
            );
        }
        for v in [
            ReviewVerdict::Correct,
            ReviewVerdict::Borderline,
            ReviewVerdict::Incorrect,
            ReviewVerdict::Unsafe,
            ReviewVerdict::Inconclusive,
        ] {
            assert_eq!(
                v,
                serde_json::from_str::<ReviewVerdict>(&serde_json::to_string(&v).unwrap()).unwrap()
            );
        }
    }
}
