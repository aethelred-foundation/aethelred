//! Infrastructure configuration-drift register.
//!
//! Maps to **SOC 2 CC8.1** (configuration change control), **NIST 800-53
//! CM-8** (information system component inventory), and CIS controls
//! 4.1-4.3 (continuous configuration monitoring). When the **declared**
//! state of an infrastructure resource (Terraform state, Kubernetes
//! manifest, GitOps source) diverges from the **actual** observed state
//! (cloud-API readback, kubectl get), that's *drift* — and every drift
//! incident must be detected, classified, owned, and either remediated
//! (re-apply declared) or accepted (update declared to match actual).
//!
//! Distinct from [`crate::terraform_plan_register`] (planned changes)
//! and [`crate::kubernetes_manifest_register`] (declared K8s state):
//! this is the **divergence detector** that compares the two against
//! observed reality.
//!
//! ## Lifecycle
//!
//! `Detected → Triaged → (RemediationPlanned → Remediated) | Accepted | FalsePositive`
//!
//! Re-detection is allowed (Remediated → Detected) — once a drift is
//! cleared, if the resource drifts again the new instance opens a fresh
//! record.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// DriftSource
// =============================================================================

/// Where the declared state lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSource {
    /// Terraform state.
    Terraform,
    /// Kubernetes manifest (GitOps).
    Kubernetes,
    /// Pulumi state.
    Pulumi,
    /// CloudFormation stack.
    CloudFormation,
    /// Helm release values.
    Helm,
    /// Ansible playbook.
    Ansible,
    /// Other / custom.
    Other,
}

// =============================================================================
// DriftSeverity
// =============================================================================

/// Severity of the drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// Informational — cosmetic / metadata only.
    Info,
    /// Low — non-functional config differences.
    Low,
    /// Medium — functional difference, no security impact.
    Medium,
    /// High — security or availability impact.
    High,
    /// Critical — actively dangerous (open-port, missing-policy, etc.).
    Critical,
}

impl DriftSeverity {
    /// Numeric rank.
    pub fn rank(self) -> u8 {
        match self {
            Self::Info => 1,
            Self::Low => 2,
            Self::Medium => 3,
            Self::High => 4,
            Self::Critical => 5,
        }
    }

    /// True if remediation should be prioritised (High or Critical).
    pub fn is_actionable(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

// =============================================================================
// DriftStage
// =============================================================================

/// Lifecycle stage of a drift record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftStage {
    /// First detected; not yet triaged.
    Detected,
    /// Triaged — owner + severity + plan-of-record assigned.
    Triaged,
    /// Remediation plan documented; awaiting execution.
    RemediationPlanned,
    /// Re-applied declared state; cluster back in sync.
    Remediated,
    /// Drift accepted — declared state was updated to match actual.
    Accepted,
    /// Triage determined this was not real drift.
    FalsePositive,
}

impl DriftStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Remediated | Self::Accepted | Self::FalsePositive
        )
    }

    /// True if drift is currently open and needs action.
    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Detected | Self::Triaged | Self::RemediationPlanned
        )
    }
}

// =============================================================================
// FieldDelta
// =============================================================================

/// One field-level delta between declared and actual.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldDelta {
    /// Field path (JSONPath / dotted: "spec.replicas",
    /// "tags.environment").
    pub path: String,
    /// Declared value (JSON-stringified).
    pub declared: String,
    /// Actual value (JSON-stringified).
    pub actual: String,
}

// =============================================================================
// DriftEvent
// =============================================================================

/// One event on the drift timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: DriftStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// DriftRecord
// =============================================================================

/// One drift detection record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DriftRecord {
    /// Unique drift id.
    pub drift_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Source (where declared state lives).
    pub source: DriftSource,
    /// Resource address ("aws_instance.web", "Deployment/billing/api").
    pub resource_address: String,
    /// Optional environment ("prod", "staging").
    pub environment: Option<String>,
    /// Field-level deltas.
    pub deltas: Vec<FieldDelta>,
    /// Severity (set during triage).
    pub severity: DriftSeverity,
    /// Stage.
    pub stage: DriftStage,
    /// Owner (set during triage).
    pub owner: Option<String>,
    /// Linked Terraform plan / K8s manifest id used to declare this resource.
    pub linked_declared: Option<String>,
    /// Free-text remediation plan.
    pub remediation_plan: Option<String>,
    /// RFC 3339 — first detected.
    pub detected_at: String,
    /// RFC 3339 — terminal.
    pub closed_at: Option<String>,
    /// Final outcome summary.
    pub final_summary: Option<String>,
    /// Event timeline.
    pub events: Vec<DriftEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl DriftRecord {
    /// New `Detected` record with default Info severity (raised during
    /// triage).
    pub fn new(
        drift_id: impl Into<String>,
        tenant_id: impl Into<String>,
        source: DriftSource,
        resource_address: impl Into<String>,
        detected_at: impl Into<String>,
    ) -> Self {
        Self {
            drift_id: drift_id.into(),
            tenant_id: tenant_id.into(),
            source,
            resource_address: resource_address.into(),
            environment: None,
            deltas: Vec::new(),
            severity: DriftSeverity::Info,
            stage: DriftStage::Detected,
            owner: None,
            linked_declared: None,
            remediation_plan: None,
            detected_at: detected_at.into(),
            closed_at: None,
            final_summary: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// True if `now - detected_at` exceeds `days` and the drift is still
    /// open.
    pub fn is_aged(&self, now: &str, days: u32) -> bool {
        if !self.stage.is_open() {
            return false;
        }
        match age_in_days(&self.detected_at, now) {
            Some(d) => d >= days as i64,
            None => false,
        }
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

fn legal_transition(from: DriftStage, to: DriftStage) -> bool {
    use DriftStage::*;
    matches!(
        (from, to),
        (Detected, Triaged)
            | (Detected, FalsePositive)
            | (Triaged, RemediationPlanned)
            | (Triaged, Accepted)
            | (Triaged, FalsePositive)
            | (Triaged, Detected)         // re-triage after info update
            | (RemediationPlanned, Remediated)
            | (RemediationPlanned, Accepted)
            | (RemediationPlanned, Triaged) // plan rejected, back to triage
    )
}

// =============================================================================
// InfrastructureDriftRegister
// =============================================================================

/// Thread-safe drift register.
#[derive(Debug, Default)]
pub struct InfrastructureDriftRegister {
    inner: RwLock<HashMap<String, DriftRecord>>,
}

impl InfrastructureDriftRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new detection.
    pub fn detect(&self, record: DriftRecord) -> SandboxResult<()> {
        if !matches!(record.stage, DriftStage::Detected) {
            return Err(SandboxError::Other(format!(
                "drift must start Detected, got {:?}",
                record.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        if g.contains_key(&record.drift_id) {
            return Err(SandboxError::Other(format!(
                "drift already detected: {}",
                record.drift_id
            )));
        }
        g.insert(record.drift_id.clone(), record);
        Ok(())
    }

    /// Add a field-level delta. Allowed in Detected or Triaged.
    pub fn add_delta(&self, drift_id: &str, delta: FieldDelta) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        if !matches!(r.stage, DriftStage::Detected | DriftStage::Triaged) {
            return Err(SandboxError::Other(format!(
                "cannot add delta to {drift_id}: stage is {:?}",
                r.stage
            )));
        }
        r.deltas.push(delta);
        Ok(())
    }

    /// Triage: assign owner + severity (Detected → Triaged).
    pub fn triage(
        &self,
        drift_id: &str,
        owner: impl Into<String>,
        severity: DriftSeverity,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        if !legal_transition(r.stage, DriftStage::Triaged) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Triaged",
                r.stage
            )));
        }
        let when = at.into();
        let owner = owner.into();
        r.stage = DriftStage::Triaged;
        r.owner = Some(owner.clone());
        r.severity = severity;
        r.events.push(DriftEvent {
            at: when,
            actor: owner,
            stage: DriftStage::Triaged,
            note: note.into(),
        });
        Ok(r.clone())
    }

    /// Plan remediation (Triaged → RemediationPlanned).
    pub fn plan_remediation(
        &self,
        drift_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        plan: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        if !legal_transition(r.stage, DriftStage::RemediationPlanned) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> RemediationPlanned",
                r.stage
            )));
        }
        let when = at.into();
        let plan = plan.into();
        r.stage = DriftStage::RemediationPlanned;
        r.remediation_plan = Some(plan.clone());
        r.events.push(DriftEvent {
            at: when,
            actor: actor.into(),
            stage: DriftStage::RemediationPlanned,
            note: plan,
        });
        Ok(r.clone())
    }

    /// Mark Remediated.
    pub fn remediated(
        &self,
        drift_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        summary: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        self.terminal_transition(
            drift_id,
            DriftStage::Remediated,
            actor,
            at,
            summary,
        )
    }

    /// Mark Accepted.
    pub fn accept(
        &self,
        drift_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        self.terminal_transition(
            drift_id,
            DriftStage::Accepted,
            actor,
            at,
            reason,
        )
    }

    /// Mark FalsePositive (allowed from Detected or Triaged).
    pub fn mark_false_positive(
        &self,
        drift_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        self.terminal_transition(
            drift_id,
            DriftStage::FalsePositive,
            actor,
            at,
            reason,
        )
    }

    fn terminal_transition(
        &self,
        drift_id: &str,
        new_stage: DriftStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<DriftRecord> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        let note = note.into();
        r.stage = new_stage;
        r.closed_at = Some(when.clone());
        r.final_summary = Some(note.clone());
        r.events.push(DriftEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note,
        });
        Ok(r.clone())
    }

    /// Set environment.
    pub fn set_environment(
        &self,
        drift_id: &str,
        environment: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        r.environment = Some(environment.into());
        Ok(())
    }

    /// Set linked declared id (Terraform plan / K8s manifest).
    pub fn set_linked_declared(
        &self,
        drift_id: &str,
        linked: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        r.linked_declared = Some(linked.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, drift_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("drift register poisoned".into()))?;
        let r = g
            .get_mut(drift_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown drift {drift_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, drift_id: &str) -> Option<DriftRecord> {
        let g = self.inner.read().ok()?;
        g.get(drift_id).cloned()
    }

    /// All records.
    pub fn all(&self) -> Vec<DriftRecord> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Records for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<DriftRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Records for an environment.
    pub fn for_environment(&self, environment: &str) -> Vec<DriftRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.environment.as_deref() == Some(environment))
            .collect()
    }

    /// Records by source.
    pub fn by_source(&self, source: DriftSource) -> Vec<DriftRecord> {
        self.all().into_iter().filter(|r| r.source == source).collect()
    }

    /// Records by stage.
    pub fn by_stage(&self, stage: DriftStage) -> Vec<DriftRecord> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Open records.
    pub fn open(&self) -> Vec<DriftRecord> {
        self.all().into_iter().filter(|r| r.stage.is_open()).collect()
    }

    /// Open records of High or Critical severity.
    pub fn actionable(&self) -> Vec<DriftRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.stage.is_open() && r.severity.is_actionable())
            .collect()
    }

    /// Records older than `days` and still open.
    pub fn aged(&self, now: &str, days: u32) -> Vec<DriftRecord> {
        self.all()
            .into_iter()
            .filter(|r| r.is_aged(now, days))
            .collect()
    }

    /// Number of records.
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

    fn drift(id: &str) -> DriftRecord {
        DriftRecord::new(
            id,
            "tenant-a",
            DriftSource::Terraform,
            "aws_instance.web",
            "2025-04-01T00:00:00Z",
        )
    }

    fn delta(path: &str, declared: &str, actual: &str) -> FieldDelta {
        FieldDelta {
            path: path.into(),
            declared: declared.into(),
            actual: actual.into(),
        }
    }

    #[test]
    fn detect_and_get() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        assert!(r.get("d1").is_some());
    }

    #[test]
    fn duplicate_detect_errors() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        let err = r.detect(drift("d1")).unwrap_err();
        assert!(format!("{err}").contains("already detected"));
    }

    #[test]
    fn must_start_detected() {
        let mut d = drift("d1");
        d.stage = DriftStage::Triaged;
        let r = InfrastructureDriftRegister::new();
        let err = r.detect(d).unwrap_err();
        assert!(format!("{err}").contains("must start Detected"));
    }

    #[test]
    fn legal_transitions() {
        use DriftStage::*;
        assert!(legal_transition(Detected, Triaged));
        assert!(legal_transition(Detected, FalsePositive));
        assert!(legal_transition(Triaged, RemediationPlanned));
        assert!(legal_transition(Triaged, Accepted));
        assert!(legal_transition(Triaged, Detected));
        assert!(legal_transition(RemediationPlanned, Remediated));
        assert!(legal_transition(RemediationPlanned, Accepted));
        assert!(legal_transition(RemediationPlanned, Triaged));
        // illegal
        assert!(!legal_transition(Detected, Remediated));
        assert!(!legal_transition(Remediated, Detected));
        assert!(!legal_transition(Accepted, Triaged));
    }

    #[test]
    fn happy_path_remediation() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.add_delta("d1", delta("spec.replicas", "3", "5")).unwrap();
        r.triage(
            "d1",
            "platform",
            DriftSeverity::Medium,
            "2025-04-02T00:00:00Z",
            "manually scaled by ops",
        )
        .unwrap();
        r.plan_remediation(
            "d1",
            "platform",
            "2025-04-03T00:00:00Z",
            "re-apply tf state to scale back to 3",
        )
        .unwrap();
        let d = r
            .remediated(
                "d1",
                "platform",
                "2025-04-04T00:00:00Z",
                "tf apply succeeded",
            )
            .unwrap();
        assert_eq!(d.stage, DriftStage::Remediated);
        assert!(d.stage.is_terminal());
        assert_eq!(d.severity, DriftSeverity::Medium);
        assert_eq!(d.events.len(), 3); // triaged, planned, remediated
    }

    #[test]
    fn accept_drift() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.triage(
            "d1",
            "platform",
            DriftSeverity::Low,
            "2025-04-02T00:00:00Z",
            "operator change is correct",
        )
        .unwrap();
        let d = r
            .accept(
                "d1",
                "platform",
                "2025-04-03T00:00:00Z",
                "TF source updated to match",
            )
            .unwrap();
        assert_eq!(d.stage, DriftStage::Accepted);
        assert!(d.stage.is_terminal());
    }

    #[test]
    fn mark_false_positive() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        let d = r
            .mark_false_positive(
                "d1",
                "platform",
                "2025-04-02T00:00:00Z",
                "scanner bug",
            )
            .unwrap();
        assert_eq!(d.stage, DriftStage::FalsePositive);
        assert!(!d.stage.is_open());
    }

    // Note: the Triaged → Detected re-triage edge is asserted in
    // `legal_transitions` above; there's no public method that triggers it
    // alone (it would correspond to a "re-detect" call which the
    // protocol's external scanner would emit as a fresh Detected record),
    // so no per-method test is needed here.

    #[test]
    fn illegal_transitions_error() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        // Detected → Remediated is illegal.
        let err = r
            .remediated("d1", "x", "2025-04-02T00:00:00Z", "n")
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_delta_after_remediation_planned_errors() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.triage(
            "d1",
            "x",
            DriftSeverity::Low,
            "2025-04-02T00:00:00Z",
            "n",
        )
        .unwrap();
        r.plan_remediation("d1", "x", "2025-04-03T00:00:00Z", "n")
            .unwrap();
        let err = r.add_delta("d1", delta("a", "1", "2")).unwrap_err();
        assert!(format!("{err}").contains("cannot add delta"));
    }

    #[test]
    fn set_env_link_tag() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.set_environment("d1", "prod").unwrap();
        r.set_linked_declared("d1", "TF-PLAN-007").unwrap();
        r.add_tag("d1", "p0").unwrap();
        r.add_tag("d1", "p0").unwrap();
        let d = r.get("d1").unwrap();
        assert_eq!(d.environment.as_deref(), Some("prod"));
        assert_eq!(d.linked_declared.as_deref(), Some("TF-PLAN-007"));
        assert_eq!(d.tags, vec!["p0"]);
    }

    #[test]
    fn unknown_drift_errors() {
        let r = InfrastructureDriftRegister::new();
        let err = r.set_environment("nope", "prod").unwrap_err();
        assert!(format!("{err}").contains("unknown drift"));
    }

    #[test]
    fn for_tenant_filter() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        let mut other = drift("d2");
        other.tenant_id = "tenant-b".into();
        r.detect(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn for_environment_filter() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.detect(drift("d2")).unwrap();
        r.set_environment("d1", "prod").unwrap();
        r.set_environment("d2", "staging").unwrap();
        assert_eq!(r.for_environment("prod").len(), 1);
        assert_eq!(r.for_environment("staging").len(), 1);
        assert_eq!(r.for_environment("dev").len(), 0);
    }

    #[test]
    fn by_source_by_stage_filters() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        let mut k8s = drift("d2");
        k8s.source = DriftSource::Kubernetes;
        r.detect(k8s).unwrap();
        assert_eq!(r.by_source(DriftSource::Terraform).len(), 1);
        assert_eq!(r.by_source(DriftSource::Kubernetes).len(), 1);
        assert_eq!(r.by_stage(DriftStage::Detected).len(), 2);
    }

    #[test]
    fn open_filter() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.detect(drift("d2")).unwrap();
        r.mark_false_positive(
            "d2",
            "x",
            "2025-04-02T00:00:00Z",
            "n",
        )
        .unwrap();
        assert_eq!(r.open().len(), 1);
        assert_eq!(r.open()[0].drift_id, "d1");
    }

    #[test]
    fn actionable_filter() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        r.detect(drift("d2")).unwrap();
        r.detect(drift("d3")).unwrap();
        r.triage("d1", "x", DriftSeverity::Critical, "2025-04-02T00:00:00Z", "n")
            .unwrap();
        r.triage("d2", "x", DriftSeverity::Low, "2025-04-02T00:00:00Z", "n")
            .unwrap();
        r.triage("d3", "x", DriftSeverity::High, "2025-04-02T00:00:00Z", "n")
            .unwrap();
        let act = r.actionable();
        let ids: Vec<_> = act.iter().map(|d| d.drift_id.clone()).collect();
        assert!(ids.contains(&"d1".to_string()));
        assert!(ids.contains(&"d3".to_string()));
        assert!(!ids.contains(&"d2".to_string()));
    }

    #[test]
    fn aged_query() {
        let r = InfrastructureDriftRegister::new();
        r.detect(drift("d1")).unwrap();
        // 35 days later, threshold 30 days → aged
        assert_eq!(r.aged("2025-05-06T00:00:00Z", 30).len(), 1);
        // 5 days later → not aged
        assert_eq!(r.aged("2025-04-06T00:00:00Z", 30).len(), 0);
        // Closed → not aged
        r.mark_false_positive("d1", "x", "2025-04-06T00:00:00Z", "n").unwrap();
        assert_eq!(r.aged("2025-05-06T00:00:00Z", 30).len(), 0);
    }

    #[test]
    fn severity_helpers() {
        assert!(DriftSeverity::Critical.is_actionable());
        assert!(DriftSeverity::High.is_actionable());
        assert!(!DriftSeverity::Medium.is_actionable());
        assert!(DriftSeverity::Critical.rank() > DriftSeverity::High.rank());
    }

    #[test]
    fn stage_helpers() {
        for s in [
            DriftStage::Detected,
            DriftStage::Triaged,
            DriftStage::RemediationPlanned,
        ] {
            assert!(s.is_open());
            assert!(!s.is_terminal());
        }
        for s in [
            DriftStage::Remediated,
            DriftStage::Accepted,
            DriftStage::FalsePositive,
        ] {
            assert!(!s.is_open());
            assert!(s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = InfrastructureDriftRegister::new();
        assert_eq!(r.count(), 0);
        r.detect(drift("d1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn drift_serde() {
        let d = drift("d1");
        let j = serde_json::to_string(&d).unwrap();
        let back: DriftRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn enums_serde() {
        for src in [
            DriftSource::Terraform,
            DriftSource::Kubernetes,
            DriftSource::Pulumi,
            DriftSource::CloudFormation,
            DriftSource::Helm,
            DriftSource::Ansible,
            DriftSource::Other,
        ] {
            assert_eq!(
                src,
                serde_json::from_str::<DriftSource>(&serde_json::to_string(&src).unwrap()).unwrap()
            );
        }
        for sev in [
            DriftSeverity::Info,
            DriftSeverity::Low,
            DriftSeverity::Medium,
            DriftSeverity::High,
            DriftSeverity::Critical,
        ] {
            assert_eq!(
                sev,
                serde_json::from_str::<DriftSeverity>(&serde_json::to_string(&sev).unwrap())
                    .unwrap()
            );
        }
        for s in [
            DriftStage::Detected,
            DriftStage::Triaged,
            DriftStage::RemediationPlanned,
            DriftStage::Remediated,
            DriftStage::Accepted,
            DriftStage::FalsePositive,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<DriftStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
