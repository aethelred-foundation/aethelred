//! Capacity-planning register — utilization observations, forecasts, and
//! scaling recommendations.
//!
//! Maps to **FinOps Foundation "Optimize"** capability (right-sizing),
//! **SOC 2 A1.1** (availability commitments), and **NIST 800-53 SC-5**
//! (denial-of-service / capacity protection). The register holds two
//! distinct artefacts:
//!
//! - **[`UtilizationSample`]** — observed metric points (CPU %, memory
//!   GB, request RPS) bucketed per resource. Stored as a rolling buffer
//!   so old samples FIFO-evict.
//! - **[`CapacityRecommendation`]** — operator-facing recommendations
//!   (`ScaleUp`, `ScaleDown`, `ScaleOut`, `ScaleIn`, `RightSize`,
//!   `Migrate`) with lifecycle
//!   `Open → InReview → (Accepted → Implemented) | Rejected | Stale`.
//!
//! Distinct from [`crate::operational_baseline`] (statistical drift
//! detection) and [`crate::edge_node_registry`] (fleet inventory): this
//! module specifically answers "is this resource right-sized for its
//! observed load, and what should we do about it?"

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// MetricKind
// =============================================================================

/// Capacity metric kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricKind {
    /// CPU utilisation as percent of provisioned (0-100, but spike-prone
    /// beyond on multi-core).
    CpuPercent,
    /// Memory utilisation in megabytes.
    MemoryMb,
    /// Storage usage in gigabytes.
    StorageGb,
    /// Network ingress bytes per second.
    NetworkIngressBps,
    /// Network egress bytes per second.
    NetworkEgressBps,
    /// Request rate (RPS).
    RequestRate,
    /// Request latency p99 in milliseconds.
    LatencyP99Ms,
    /// Connection count.
    Connections,
    /// Custom application metric.
    Custom,
}

// =============================================================================
// UtilizationSample
// =============================================================================

/// One observed metric sample.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UtilizationSample {
    /// RFC 3339.
    pub at: String,
    /// Metric kind.
    pub metric: MetricKind,
    /// Numeric value.
    pub value: f64,
}

// =============================================================================
// ResourceCapacity
// =============================================================================

/// Capacity record for one resource (a VM, container set, database,
/// service tier).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceCapacity {
    /// Stable resource id.
    pub resource_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Resource type ("aws-ec2", "k8s-deployment", "rds-instance").
    pub resource_type: String,
    /// Provisioned capacity vector (declared limits at creation time).
    pub provisioned: Vec<(MetricKind, f64)>,
    /// Sample buffer (FIFO-evicted at `sample_capacity`).
    pub samples: Vec<UtilizationSample>,
    /// Maximum samples retained.
    pub sample_capacity: usize,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl ResourceCapacity {
    /// Construct a new capacity record.
    pub fn new(
        resource_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        resource_type: impl Into<String>,
        sample_capacity: usize,
    ) -> Self {
        Self {
            resource_id: resource_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            resource_type: resource_type.into(),
            provisioned: Vec::new(),
            samples: Vec::new(),
            sample_capacity,
            tags: Vec::new(),
        }
    }

    /// Provisioned value for a metric, if any.
    pub fn provisioned_for(&self, metric: MetricKind) -> Option<f64> {
        self.provisioned
            .iter()
            .find(|(k, _)| *k == metric)
            .map(|(_, v)| *v)
    }

    /// Mean of `metric` samples, or `None` if no samples for that metric.
    pub fn mean_for(&self, metric: MetricKind) -> Option<f64> {
        let values: Vec<f64> = self
            .samples
            .iter()
            .filter(|s| s.metric == metric)
            .map(|s| s.value)
            .collect();
        if values.is_empty() {
            return None;
        }
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }

    /// Maximum of `metric` samples.
    pub fn max_for(&self, metric: MetricKind) -> Option<f64> {
        self.samples
            .iter()
            .filter(|s| s.metric == metric)
            .map(|s| s.value)
            .fold(None, |acc, v| match acc {
                None => Some(v),
                Some(m) if v > m => Some(v),
                Some(m) => Some(m),
            })
    }

    /// Mean utilisation as a fraction of provisioned (0.0-1.0+, can
    /// exceed 1.0 if observed beyond limits). `None` if either is missing.
    pub fn mean_utilisation(&self, metric: MetricKind) -> Option<f64> {
        let prov = self.provisioned_for(metric)?;
        if prov == 0.0 {
            return None;
        }
        let mean = self.mean_for(metric)?;
        Some(mean / prov)
    }
}

// =============================================================================
// RecommendationKind
// =============================================================================

/// Kind of capacity recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationKind {
    /// Increase per-instance size (vertical up).
    ScaleUp,
    /// Decrease per-instance size (vertical down).
    ScaleDown,
    /// Add more instances (horizontal out).
    ScaleOut,
    /// Remove instances (horizontal in).
    ScaleIn,
    /// Right-size — adjust provisioned vector to closely match observed.
    RightSize,
    /// Migrate to different resource type entirely.
    Migrate,
}

impl RecommendationKind {
    /// True if this recommendation reduces cost (downsize / scale in).
    pub fn is_cost_saving(self) -> bool {
        matches!(self, Self::ScaleDown | Self::ScaleIn | Self::RightSize)
    }
}

// =============================================================================
// RecommendationStage
// =============================================================================

/// Lifecycle stage of a recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationStage {
    /// Issued by the planner; awaiting human review.
    Open,
    /// Engineer reviewing.
    InReview,
    /// Approved; awaiting implementation.
    Accepted,
    /// Action implemented.
    Implemented,
    /// Rejected.
    Rejected,
    /// Aged out without action (stale recommendation).
    Stale,
}

impl RecommendationStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Implemented | Self::Rejected | Self::Stale)
    }
}

// =============================================================================
// CapacityRecommendation
// =============================================================================

/// One operator-facing capacity recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapacityRecommendation {
    /// Unique id.
    pub recommendation_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Resource being recommended on.
    pub resource_id: String,
    /// Kind.
    pub kind: RecommendationKind,
    /// Free-text rationale.
    pub rationale: String,
    /// Suggested target (free-form, e.g., "m5.large", "replicas=8",
    /// "memory=512MB").
    pub suggested_target: String,
    /// Estimated monthly cost delta in micro-units (negative = saving,
    /// positive = increase).
    pub estimated_cost_delta_micro: i64,
    /// Stage.
    pub stage: RecommendationStage,
    /// Owner.
    pub owner: Option<String>,
    /// RFC 3339 — issued.
    pub issued_at: String,
    /// RFC 3339 — closed (terminal stage).
    pub closed_at: Option<String>,
    /// Final outcome summary.
    pub outcome: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl CapacityRecommendation {
    /// New `Open` recommendation.
    pub fn new(
        recommendation_id: impl Into<String>,
        tenant_id: impl Into<String>,
        resource_id: impl Into<String>,
        kind: RecommendationKind,
        rationale: impl Into<String>,
        suggested_target: impl Into<String>,
        estimated_cost_delta_micro: i64,
        issued_at: impl Into<String>,
    ) -> Self {
        Self {
            recommendation_id: recommendation_id.into(),
            tenant_id: tenant_id.into(),
            resource_id: resource_id.into(),
            kind,
            rationale: rationale.into(),
            suggested_target: suggested_target.into(),
            estimated_cost_delta_micro,
            stage: RecommendationStage::Open,
            owner: None,
            issued_at: issued_at.into(),
            closed_at: None,
            outcome: None,
            tags: Vec::new(),
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RecommendationStage, to: RecommendationStage) -> bool {
    use RecommendationStage::*;
    matches!(
        (from, to),
        (Open, InReview)
            | (Open, Stale)
            | (Open, Rejected)
            | (InReview, Accepted)
            | (InReview, Rejected)
            | (InReview, Stale)
            | (Accepted, Implemented)
            | (Accepted, Rejected)
            | (Accepted, Stale)
    )
}

// =============================================================================
// CapacityPlanningRegistry
// =============================================================================

/// Thread-safe registry of capacity records and recommendations.
#[derive(Debug, Default)]
pub struct CapacityPlanningRegistry {
    resources: RwLock<HashMap<String, ResourceCapacity>>,
    recommendations: RwLock<HashMap<String, CapacityRecommendation>>,
}

impl CapacityPlanningRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a resource.
    pub fn register_resource(&self, resource: ResourceCapacity) -> SandboxResult<()> {
        let mut g = self
            .resources
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        if g.contains_key(&resource.resource_id) {
            return Err(SandboxError::Other(format!(
                "resource already registered: {}",
                resource.resource_id
            )));
        }
        g.insert(resource.resource_id.clone(), resource);
        Ok(())
    }

    /// Set provisioned capacity for a metric.
    pub fn set_provisioned(
        &self,
        resource_id: &str,
        metric: MetricKind,
        value: f64,
    ) -> SandboxResult<()> {
        let mut g = self
            .resources
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        let r = g
            .get_mut(resource_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown resource {resource_id}")))?;
        if let Some(entry) = r.provisioned.iter_mut().find(|(k, _)| *k == metric) {
            entry.1 = value;
        } else {
            r.provisioned.push((metric, value));
        }
        Ok(())
    }

    /// Add a sample. Capacity-bounded by `sample_capacity` (FIFO eviction).
    pub fn add_sample(
        &self,
        resource_id: &str,
        sample: UtilizationSample,
    ) -> SandboxResult<()> {
        let mut g = self
            .resources
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        let r = g
            .get_mut(resource_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown resource {resource_id}")))?;
        if r.sample_capacity == 0 {
            // Pathological — drop sample.
            return Ok(());
        }
        while r.samples.len() >= r.sample_capacity {
            r.samples.remove(0);
        }
        r.samples.push(sample);
        Ok(())
    }

    /// Add a tag to a resource (deduplicated).
    pub fn add_resource_tag(
        &self,
        resource_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .resources
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        let r = g
            .get_mut(resource_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown resource {resource_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up a resource.
    pub fn get_resource(&self, resource_id: &str) -> Option<ResourceCapacity> {
        let g = self.resources.read().ok()?;
        g.get(resource_id).cloned()
    }

    /// All resources.
    pub fn all_resources(&self) -> Vec<ResourceCapacity> {
        match self.resources.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Resources for a tenant.
    pub fn resources_for_tenant(&self, tenant_id: &str) -> Vec<ResourceCapacity> {
        self.all_resources()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Resources whose mean utilisation on `metric` is below
    /// `under_threshold` (e.g., 0.30 = under-utilised).
    pub fn under_utilised(
        &self,
        metric: MetricKind,
        under_threshold: f64,
    ) -> Vec<ResourceCapacity> {
        self.all_resources()
            .into_iter()
            .filter(|r| match r.mean_utilisation(metric) {
                Some(u) => u < under_threshold,
                None => false,
            })
            .collect()
    }

    /// Resources whose mean utilisation on `metric` is above
    /// `over_threshold` (e.g., 0.85 = over-utilised, ripe for scale-up).
    pub fn over_utilised(
        &self,
        metric: MetricKind,
        over_threshold: f64,
    ) -> Vec<ResourceCapacity> {
        self.all_resources()
            .into_iter()
            .filter(|r| match r.mean_utilisation(metric) {
                Some(u) => u > over_threshold,
                None => false,
            })
            .collect()
    }

    /// Issue a recommendation. Errors if recommendation_id collides or
    /// the referenced resource is unknown / tenant-mismatched.
    pub fn issue(&self, rec: CapacityRecommendation) -> SandboxResult<()> {
        if !matches!(rec.stage, RecommendationStage::Open) {
            return Err(SandboxError::Other(format!(
                "recommendation must start Open, got {:?}",
                rec.stage
            )));
        }
        let res_tenant = {
            let rg = self
                .resources
                .read()
                .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
            let r = rg.get(&rec.resource_id).ok_or_else(|| {
                SandboxError::Other(format!("unknown resource {}", rec.resource_id))
            })?;
            r.tenant_id.clone()
        };
        if res_tenant != rec.tenant_id {
            return Err(SandboxError::Other(format!(
                "tenant mismatch: recommendation {} vs resource {}",
                rec.tenant_id, res_tenant
            )));
        }
        let mut g = self
            .recommendations
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        if g.contains_key(&rec.recommendation_id) {
            return Err(SandboxError::Other(format!(
                "recommendation already issued: {}",
                rec.recommendation_id
            )));
        }
        g.insert(rec.recommendation_id.clone(), rec);
        Ok(())
    }

    /// Apply a stage transition.
    pub fn transition(
        &self,
        recommendation_id: &str,
        new_stage: RecommendationStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        outcome: Option<String>,
    ) -> SandboxResult<CapacityRecommendation> {
        let mut g = self
            .recommendations
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        let r = g.get_mut(recommendation_id).ok_or_else(|| {
            SandboxError::Other(format!("unknown recommendation {recommendation_id}"))
        })?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        r.stage = new_stage;
        if matches!(new_stage, RecommendationStage::InReview) {
            r.owner = Some(actor.into());
        } else {
            let _ = actor;
        }
        if new_stage.is_terminal() {
            r.closed_at = Some(when);
            if let Some(o) = outcome.clone() {
                r.outcome = Some(o);
            }
        }
        Ok(r.clone())
    }

    /// Add a tag to a recommendation (deduplicated).
    pub fn add_recommendation_tag(
        &self,
        recommendation_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .recommendations
            .write()
            .map_err(|_| SandboxError::Other("capacity registry poisoned".into()))?;
        let r = g.get_mut(recommendation_id).ok_or_else(|| {
            SandboxError::Other(format!("unknown recommendation {recommendation_id}"))
        })?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get_recommendation(
        &self,
        recommendation_id: &str,
    ) -> Option<CapacityRecommendation> {
        let g = self.recommendations.read().ok()?;
        g.get(recommendation_id).cloned()
    }

    /// All recommendations.
    pub fn all_recommendations(&self) -> Vec<CapacityRecommendation> {
        match self.recommendations.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Recommendations for a tenant.
    pub fn recommendations_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<CapacityRecommendation> {
        self.all_recommendations()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Recommendations for a resource.
    pub fn recommendations_for_resource(
        &self,
        resource_id: &str,
    ) -> Vec<CapacityRecommendation> {
        self.all_recommendations()
            .into_iter()
            .filter(|r| r.resource_id == resource_id)
            .collect()
    }

    /// Recommendations by stage.
    pub fn by_stage(&self, stage: RecommendationStage) -> Vec<CapacityRecommendation> {
        self.all_recommendations()
            .into_iter()
            .filter(|r| r.stage == stage)
            .collect()
    }

    /// Open recommendations.
    pub fn open(&self) -> Vec<CapacityRecommendation> {
        self.all_recommendations()
            .into_iter()
            .filter(|r| !r.stage.is_terminal())
            .collect()
    }

    /// Cost-saving recommendations (kind is downsize-style).
    pub fn cost_saving(&self) -> Vec<CapacityRecommendation> {
        self.all_recommendations()
            .into_iter()
            .filter(|r| r.kind.is_cost_saving())
            .collect()
    }

    /// Total estimated saving (negative micro-units across all
    /// non-rejected, non-stale cost-saving recommendations).
    pub fn estimated_total_saving_micro(&self) -> i64 {
        self.all_recommendations()
            .into_iter()
            .filter(|r| {
                r.kind.is_cost_saving()
                    && !matches!(
                        r.stage,
                        RecommendationStage::Rejected | RecommendationStage::Stale
                    )
                    && r.estimated_cost_delta_micro < 0
            })
            .map(|r| r.estimated_cost_delta_micro)
            .sum()
    }

    /// Counts.
    pub fn resource_count(&self) -> usize {
        self.resources.read().map(|g| g.len()).unwrap_or(0)
    }

    /// Counts.
    pub fn recommendation_count(&self) -> usize {
        self.recommendations.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn res(id: &str, cap: usize) -> ResourceCapacity {
        ResourceCapacity::new(id, "tenant-a", format!("name-{id}"), "k8s-deployment", cap)
    }

    fn sample(at: &str, metric: MetricKind, value: f64) -> UtilizationSample {
        UtilizationSample {
            at: at.into(),
            metric,
            value,
        }
    }

    fn rec(rid: &str, resource_id: &str, kind: RecommendationKind) -> CapacityRecommendation {
        CapacityRecommendation::new(
            rid,
            "tenant-a",
            resource_id,
            kind,
            "rationale",
            "m5.large",
            -100_000,
            "2025-04-01T00:00:00Z",
        )
    }

    #[test]
    fn register_and_get_resource() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        assert!(r.get_resource("r1").is_some());
    }

    #[test]
    fn duplicate_resource_errors() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        let err = r.register_resource(res("r1", 10)).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn set_provisioned_overwrite() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.set_provisioned("r1", MetricKind::CpuPercent, 100.0).unwrap();
        r.set_provisioned("r1", MetricKind::CpuPercent, 200.0).unwrap();
        let g = r.get_resource("r1").unwrap();
        assert_eq!(g.provisioned.len(), 1);
        assert_eq!(g.provisioned[0].1, 200.0);
    }

    #[test]
    fn add_sample_fifo_evicts_at_capacity() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 3)).unwrap();
        for i in 0..5 {
            r.add_sample(
                "r1",
                sample(
                    &format!("2025-04-0{}T00:00:00Z", i + 1),
                    MetricKind::CpuPercent,
                    i as f64,
                ),
            )
            .unwrap();
        }
        let g = r.get_resource("r1").unwrap();
        assert_eq!(g.samples.len(), 3);
        // Oldest evicted; newest retained.
        assert_eq!(g.samples[0].value, 2.0);
        assert_eq!(g.samples[2].value, 4.0);
    }

    #[test]
    fn zero_capacity_drops_sample() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 0)).unwrap();
        r.add_sample(
            "r1",
            sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, 50.0),
        )
        .unwrap();
        assert_eq!(r.get_resource("r1").unwrap().samples.len(), 0);
    }

    #[test]
    fn mean_max_for_metric() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        for v in [40.0, 60.0, 80.0] {
            r.add_sample(
                "r1",
                sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, v),
            )
            .unwrap();
        }
        // Add unrelated metric to ensure filtering works.
        r.add_sample(
            "r1",
            sample("2025-04-01T00:00:00Z", MetricKind::MemoryMb, 100.0),
        )
        .unwrap();
        let g = r.get_resource("r1").unwrap();
        let mean = g.mean_for(MetricKind::CpuPercent).unwrap();
        let max = g.max_for(MetricKind::CpuPercent).unwrap();
        assert!((mean - 60.0).abs() < 1e-9);
        assert_eq!(max, 80.0);
        assert_eq!(g.mean_for(MetricKind::LatencyP99Ms), None);
    }

    #[test]
    fn mean_utilisation_against_provisioned() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.set_provisioned("r1", MetricKind::CpuPercent, 100.0).unwrap();
        for v in [20.0, 30.0, 40.0] {
            r.add_sample(
                "r1",
                sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, v),
            )
            .unwrap();
        }
        let u = r
            .get_resource("r1")
            .unwrap()
            .mean_utilisation(MetricKind::CpuPercent)
            .unwrap();
        assert!((u - 0.30).abs() < 1e-9);
    }

    #[test]
    fn mean_utilisation_zero_provisioned_returns_none() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.set_provisioned("r1", MetricKind::CpuPercent, 0.0).unwrap();
        r.add_sample(
            "r1",
            sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, 50.0),
        )
        .unwrap();
        assert_eq!(
            r.get_resource("r1").unwrap().mean_utilisation(MetricKind::CpuPercent),
            None
        );
    }

    #[test]
    fn under_over_utilised_filters() {
        let r = CapacityPlanningRegistry::new();
        // r1: 30% utilisation
        r.register_resource(res("r1", 10)).unwrap();
        r.set_provisioned("r1", MetricKind::CpuPercent, 100.0).unwrap();
        for v in [25.0, 30.0, 35.0] {
            r.add_sample(
                "r1",
                sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, v),
            )
            .unwrap();
        }
        // r2: 90% utilisation
        r.register_resource(res("r2", 10)).unwrap();
        r.set_provisioned("r2", MetricKind::CpuPercent, 100.0).unwrap();
        for v in [85.0, 90.0, 95.0] {
            r.add_sample(
                "r2",
                sample("2025-04-01T00:00:00Z", MetricKind::CpuPercent, v),
            )
            .unwrap();
        }
        let under = r.under_utilised(MetricKind::CpuPercent, 0.5);
        assert_eq!(under.len(), 1);
        assert_eq!(under[0].resource_id, "r1");
        let over = r.over_utilised(MetricKind::CpuPercent, 0.85);
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].resource_id, "r2");
    }

    #[test]
    fn under_utilised_excludes_no_data() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        // No samples → not under-utilised (None excluded)
        assert!(r.under_utilised(MetricKind::CpuPercent, 0.5).is_empty());
    }

    #[test]
    fn issue_unknown_resource_errors() {
        let r = CapacityPlanningRegistry::new();
        let err = r.issue(rec("r1", "missing", RecommendationKind::ScaleDown)).unwrap_err();
        assert!(format!("{err}").contains("unknown resource"));
    }

    #[test]
    fn issue_tenant_mismatch_errors() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        let mut rc = rec("c1", "r1", RecommendationKind::ScaleDown);
        rc.tenant_id = "tenant-b".into();
        let err = r.issue(rc).unwrap_err();
        assert!(format!("{err}").contains("tenant mismatch"));
    }

    #[test]
    fn issue_must_start_open() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        let mut rc = rec("c1", "r1", RecommendationKind::ScaleDown);
        rc.stage = RecommendationStage::Implemented;
        let err = r.issue(rc).unwrap_err();
        assert!(format!("{err}").contains("must start Open"));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        r.transition(
            "c1",
            RecommendationStage::InReview,
            "platform",
            "2025-04-02T00:00:00Z",
            None,
        )
        .unwrap();
        r.transition(
            "c1",
            RecommendationStage::Accepted,
            "platform",
            "2025-04-03T00:00:00Z",
            None,
        )
        .unwrap();
        let g = r
            .transition(
                "c1",
                RecommendationStage::Implemented,
                "platform",
                "2025-04-05T00:00:00Z",
                Some("scaled to m5.medium".into()),
            )
            .unwrap();
        assert_eq!(g.stage, RecommendationStage::Implemented);
        assert!(g.stage.is_terminal());
        assert_eq!(g.outcome.as_deref(), Some("scaled to m5.medium"));
    }

    #[test]
    fn legal_transitions() {
        use RecommendationStage::*;
        assert!(legal_transition(Open, InReview));
        assert!(legal_transition(Open, Stale));
        assert!(legal_transition(Open, Rejected));
        assert!(legal_transition(InReview, Accepted));
        assert!(legal_transition(InReview, Rejected));
        assert!(legal_transition(Accepted, Implemented));
        assert!(legal_transition(Accepted, Rejected));
        // illegal
        assert!(!legal_transition(Open, Accepted));
        assert!(!legal_transition(Implemented, Open));
        assert!(!legal_transition(Rejected, Open));
    }

    #[test]
    fn illegal_transition_errors() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        let err = r
            .transition(
                "c1",
                RecommendationStage::Implemented,
                "x",
                "2025-04-02T00:00:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_resource_recommendation_tags_dedupe() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        r.add_resource_tag("r1", "prod").unwrap();
        r.add_resource_tag("r1", "prod").unwrap();
        r.add_recommendation_tag("c1", "cost-savings").unwrap();
        r.add_recommendation_tag("c1", "cost-savings").unwrap();
        assert_eq!(r.get_resource("r1").unwrap().tags, vec!["prod"]);
        assert_eq!(
            r.get_recommendation("c1").unwrap().tags,
            vec!["cost-savings"]
        );
    }

    #[test]
    fn unknown_resource_or_recommendation_errors() {
        let r = CapacityPlanningRegistry::new();
        let err = r.set_provisioned("nope", MetricKind::CpuPercent, 100.0).unwrap_err();
        assert!(format!("{err}").contains("unknown resource"));
        let err = r
            .transition("nope", RecommendationStage::InReview, "x", "2025-04-02T00:00:00Z", None)
            .unwrap_err();
        assert!(format!("{err}").contains("unknown recommendation"));
    }

    #[test]
    fn for_tenant_resource_filters() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        let mut other = res("r2", 10);
        other.tenant_id = "tenant-b".into();
        r.register_resource(other).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        r.issue(rec("c2", "r1", RecommendationKind::ScaleUp)).unwrap();
        assert_eq!(r.resources_for_tenant("tenant-a").len(), 1);
        assert_eq!(r.resources_for_tenant("tenant-b").len(), 1);
        assert_eq!(r.recommendations_for_resource("r1").len(), 2);
        assert_eq!(r.recommendations_for_tenant("tenant-a").len(), 2);
    }

    #[test]
    fn open_by_stage_filters() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        r.issue(rec("c2", "r1", RecommendationKind::ScaleUp)).unwrap();
        r.transition(
            "c2",
            RecommendationStage::Rejected,
            "x",
            "2025-04-02T00:00:00Z",
            None,
        )
        .unwrap();
        assert_eq!(r.open().len(), 1);
        assert_eq!(r.by_stage(RecommendationStage::Open).len(), 1);
        assert_eq!(r.by_stage(RecommendationStage::Rejected).len(), 1);
    }

    #[test]
    fn cost_saving_filter() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        r.issue(rec("c2", "r1", RecommendationKind::ScaleUp)).unwrap();
        r.issue(rec("c3", "r1", RecommendationKind::RightSize)).unwrap();
        let savings = r.cost_saving();
        let ids: Vec<_> = savings.iter().map(|c| c.recommendation_id.clone()).collect();
        assert!(ids.contains(&"c1".to_string()));
        assert!(ids.contains(&"c3".to_string()));
        assert!(!ids.contains(&"c2".to_string()));
    }

    #[test]
    fn estimated_total_saving_excludes_terminated() {
        let r = CapacityPlanningRegistry::new();
        r.register_resource(res("r1", 10)).unwrap();
        // Open cost-saving — counted
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        // Rejected — not counted
        r.issue(rec("c2", "r1", RecommendationKind::ScaleIn)).unwrap();
        r.transition(
            "c2",
            RecommendationStage::Rejected,
            "x",
            "2025-04-02T00:00:00Z",
            None,
        )
        .unwrap();
        // Stale — not counted
        r.issue(rec("c3", "r1", RecommendationKind::RightSize)).unwrap();
        r.transition(
            "c3",
            RecommendationStage::Stale,
            "x",
            "2025-04-02T00:00:00Z",
            None,
        )
        .unwrap();
        // Cost-increase — not counted
        let mut up = rec("c4", "r1", RecommendationKind::ScaleUp);
        up.estimated_cost_delta_micro = 200_000;
        r.issue(up).unwrap();
        // Total = -100_000 (just c1)
        assert_eq!(r.estimated_total_saving_micro(), -100_000);
    }

    #[test]
    fn kind_helpers() {
        assert!(RecommendationKind::ScaleDown.is_cost_saving());
        assert!(RecommendationKind::ScaleIn.is_cost_saving());
        assert!(RecommendationKind::RightSize.is_cost_saving());
        assert!(!RecommendationKind::ScaleUp.is_cost_saving());
        assert!(!RecommendationKind::ScaleOut.is_cost_saving());
        assert!(!RecommendationKind::Migrate.is_cost_saving());
    }

    #[test]
    fn stage_helpers() {
        for s in [
            RecommendationStage::Implemented,
            RecommendationStage::Rejected,
            RecommendationStage::Stale,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            RecommendationStage::Open,
            RecommendationStage::InReview,
            RecommendationStage::Accepted,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn counts() {
        let r = CapacityPlanningRegistry::new();
        assert_eq!(r.resource_count(), 0);
        assert_eq!(r.recommendation_count(), 0);
        r.register_resource(res("r1", 10)).unwrap();
        r.issue(rec("c1", "r1", RecommendationKind::ScaleDown)).unwrap();
        assert_eq!(r.resource_count(), 1);
        assert_eq!(r.recommendation_count(), 1);
    }

    #[test]
    fn resource_serde() {
        let res = res("r1", 10);
        let j = serde_json::to_string(&res).unwrap();
        let back: ResourceCapacity = serde_json::from_str(&j).unwrap();
        assert_eq!(res, back);
    }

    #[test]
    fn recommendation_serde() {
        let rec = rec("c1", "r1", RecommendationKind::ScaleDown);
        let j = serde_json::to_string(&rec).unwrap();
        let back: CapacityRecommendation = serde_json::from_str(&j).unwrap();
        assert_eq!(rec, back);
    }

    #[test]
    fn enums_serde() {
        for m in [
            MetricKind::CpuPercent,
            MetricKind::MemoryMb,
            MetricKind::StorageGb,
            MetricKind::NetworkIngressBps,
            MetricKind::NetworkEgressBps,
            MetricKind::RequestRate,
            MetricKind::LatencyP99Ms,
            MetricKind::Connections,
            MetricKind::Custom,
        ] {
            assert_eq!(
                m,
                serde_json::from_str::<MetricKind>(&serde_json::to_string(&m).unwrap()).unwrap()
            );
        }
        for k in [
            RecommendationKind::ScaleUp,
            RecommendationKind::ScaleDown,
            RecommendationKind::ScaleOut,
            RecommendationKind::ScaleIn,
            RecommendationKind::RightSize,
            RecommendationKind::Migrate,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<RecommendationKind>(&serde_json::to_string(&k).unwrap())
                    .unwrap()
            );
        }
        for s in [
            RecommendationStage::Open,
            RecommendationStage::InReview,
            RecommendationStage::Accepted,
            RecommendationStage::Implemented,
            RecommendationStage::Rejected,
            RecommendationStage::Stale,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RecommendationStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
    }
}
