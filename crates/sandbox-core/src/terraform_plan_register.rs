//! Terraform / Infrastructure-as-Code plan-and-apply register.
//!
//! Maps to **SOC 2 CC8.1** (change control over infrastructure),
//! **NIST 800-53 CM-3** (configuration change control), and HashiCorp
//! Sentinel / OPA policy gating norms. Every Terraform `plan` that gets
//! applied to production must be tracked from generation through review,
//! application, and (if needed) rollback — with the parsed
//! `(adds, changes, destroys)` summary, the policy verdicts, and the
//! approver chain.
//!
//! Distinct from [`crate::deployment_pipeline`] (CI/CD-stage deployment)
//! and [`crate::change_advisory_board`] (governance approval): this is
//! the **IaC artefact register** specifically — every `terraform plan`
//! file is an addressable record auditors can inspect.
//!
//! ## Lifecycle
//!
//! `Planned → Reviewed → Approved → Applying → (Applied | Failed | RolledBack)`
//!
//! Reviewers and approvers must differ from the proposer (separation of
//! duty), enforced at `approve()`. Plans that fail policy gating cannot
//! reach `Approved`.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// PlanStage
// =============================================================================

/// Lifecycle stage of an IaC plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStage {
    /// `terraform plan` was generated; under review.
    Planned,
    /// Reviewer has examined diff but not yet approved.
    Reviewed,
    /// Approver signed off; ready to apply.
    Approved,
    /// `terraform apply` in flight.
    Applying,
    /// Apply succeeded.
    Applied,
    /// Apply failed.
    Failed,
    /// Plan was discarded before apply (rejected, superseded).
    Discarded,
    /// Apply was rolled back via a counter-apply.
    RolledBack,
}

impl PlanStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Applied | Self::Failed | Self::Discarded | Self::RolledBack
        )
    }

    /// True if the plan is currently authorising production change.
    pub fn is_in_flight(self) -> bool {
        matches!(self, Self::Applying)
    }
}

// =============================================================================
// PolicyVerdict
// =============================================================================

/// Verdict from a policy gate (Sentinel / OPA / cost-policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    /// Pending evaluation.
    Pending,
    /// Passed.
    Pass,
    /// Soft-fail (advisory only).
    SoftFail,
    /// Hard-fail (blocks Approved transition).
    HardFail,
    /// Manually overridden by exec sign-off.
    Override,
}

impl PolicyVerdict {
    /// True if this verdict blocks approval.
    pub fn blocks_approval(self) -> bool {
        matches!(self, Self::Pending | Self::HardFail)
    }
}

// =============================================================================
// PolicyGate
// =============================================================================

/// One policy gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyGate {
    /// Stable id within the plan.
    pub gate_id: String,
    /// Gate name ("sentinel-cost-cap", "opa-network-policy").
    pub name: String,
    /// Verdict.
    pub verdict: PolicyVerdict,
    /// Free-text reason / output.
    pub reason: Option<String>,
}

// =============================================================================
// ResourceChangeKind
// =============================================================================

/// Kind of resource change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceChangeKind {
    /// New resource will be created.
    Create,
    /// Existing resource will be modified in place.
    Update,
    /// Existing resource will be replaced (destroy + create).
    Replace,
    /// Existing resource will be destroyed.
    Destroy,
    /// Resource will be read for data.
    Read,
}

// =============================================================================
// ResourceChange
// =============================================================================

/// One per-resource change line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceChange {
    /// Terraform resource address (e.g., "aws_instance.web[0]").
    pub address: String,
    /// Resource type ("aws_instance").
    pub resource_type: String,
    /// Kind of change.
    pub kind: ResourceChangeKind,
    /// Optional brief diff hint (sensitive content is redacted upstream).
    pub diff_summary: Option<String>,
}

// =============================================================================
// PlanEvent
// =============================================================================

/// One event on the plan timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: PlanStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// TerraformPlan
// =============================================================================

/// One IaC plan record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerraformPlan {
    /// Unique id.
    pub plan_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Workspace / environment ("prod-us-east", "staging").
    pub workspace: String,
    /// Module path or root module identifier.
    pub module: String,
    /// Plan title.
    pub title: String,
    /// Proposer (operator who ran `terraform plan`).
    pub proposer: String,
    /// Reviewer (set when entering Reviewed).
    pub reviewer: Option<String>,
    /// Approver (set when entering Approved).
    pub approver: Option<String>,
    /// Resource changes.
    pub changes: Vec<ResourceChange>,
    /// Policy gates.
    pub gates: Vec<PolicyGate>,
    /// SHA-256 of the plan bytes (tamper-evident).
    pub plan_sha256: String,
    /// Plan bytes URI (object store / artefact registry).
    pub plan_uri: Option<String>,
    /// Linked change ticket / RFC.
    pub linked_ticket: Option<String>,
    /// Stage.
    pub stage: PlanStage,
    /// RFC 3339 — generated.
    pub planned_at: String,
    /// RFC 3339 — apply started.
    pub applying_at: Option<String>,
    /// RFC 3339 — terminal.
    pub closed_at: Option<String>,
    /// Free-text final outcome.
    pub final_summary: Option<String>,
    /// Event log.
    pub events: Vec<PlanEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl TerraformPlan {
    /// New `Planned` plan.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plan_id: impl Into<String>,
        tenant_id: impl Into<String>,
        workspace: impl Into<String>,
        module: impl Into<String>,
        title: impl Into<String>,
        proposer: impl Into<String>,
        plan_sha256: impl Into<String>,
        planned_at: impl Into<String>,
    ) -> Self {
        Self {
            plan_id: plan_id.into(),
            tenant_id: tenant_id.into(),
            workspace: workspace.into(),
            module: module.into(),
            title: title.into(),
            proposer: proposer.into(),
            reviewer: None,
            approver: None,
            changes: Vec::new(),
            gates: Vec::new(),
            plan_sha256: plan_sha256.into(),
            plan_uri: None,
            linked_ticket: None,
            stage: PlanStage::Planned,
            planned_at: planned_at.into(),
            applying_at: None,
            closed_at: None,
            final_summary: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Count of resource changes by kind.
    pub fn change_counts(&self) -> (usize, usize, usize, usize) {
        let mut adds = 0;
        let mut updates = 0;
        let mut replaces = 0;
        let mut destroys = 0;
        for c in &self.changes {
            match c.kind {
                ResourceChangeKind::Create => adds += 1,
                ResourceChangeKind::Update => updates += 1,
                ResourceChangeKind::Replace => replaces += 1,
                ResourceChangeKind::Destroy => destroys += 1,
                ResourceChangeKind::Read => {}
            }
        }
        (adds, updates, replaces, destroys)
    }

    /// True if any policy gate would block approval.
    pub fn has_blocking_policy(&self) -> bool {
        self.gates.iter().any(|g| g.verdict.blocks_approval())
    }

    /// True if this plan touches destructive operations.
    pub fn is_destructive(&self) -> bool {
        self.changes.iter().any(|c| {
            matches!(
                c.kind,
                ResourceChangeKind::Destroy | ResourceChangeKind::Replace
            )
        })
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: PlanStage, to: PlanStage) -> bool {
    use PlanStage::*;
    matches!(
        (from, to),
        (Planned, Reviewed)
            | (Planned, Discarded)
            | (Reviewed, Approved)
            | (Reviewed, Planned)        // re-plan after review feedback
            | (Reviewed, Discarded)
            | (Approved, Applying)
            | (Approved, Discarded)
            | (Applying, Applied)
            | (Applying, Failed)
            | (Applied, RolledBack)      // counter-apply
            | (Failed, Planned)          // re-plan after failure
    )
}

// =============================================================================
// TerraformPlanRegister
// =============================================================================

/// Thread-safe register of Terraform plans.
#[derive(Debug, Default)]
pub struct TerraformPlanRegister {
    inner: RwLock<HashMap<String, TerraformPlan>>,
}

impl TerraformPlanRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new plan.
    pub fn register(&self, plan: TerraformPlan) -> SandboxResult<()> {
        if !matches!(plan.stage, PlanStage::Planned) {
            return Err(SandboxError::Other(format!(
                "plan must start Planned, got {:?}",
                plan.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        if g.contains_key(&plan.plan_id) {
            return Err(SandboxError::Other(format!(
                "plan already registered: {}",
                plan.plan_id
            )));
        }
        g.insert(plan.plan_id.clone(), plan);
        Ok(())
    }

    /// Add a resource change. Allowed only in Planned (immutable after).
    pub fn add_change(&self, plan_id: &str, change: ResourceChange) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if !matches!(p.stage, PlanStage::Planned) {
            return Err(SandboxError::Other(format!(
                "cannot add change to {plan_id}: stage is {:?}",
                p.stage
            )));
        }
        if p.changes.iter().any(|c| c.address == change.address) {
            return Err(SandboxError::Other(format!(
                "change address already present: {}",
                change.address
            )));
        }
        p.changes.push(change);
        Ok(())
    }

    /// Add a policy gate.
    pub fn add_gate(&self, plan_id: &str, gate: PolicyGate) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if matches!(
            p.stage,
            PlanStage::Applying | PlanStage::Applied | PlanStage::Failed | PlanStage::RolledBack
        ) {
            return Err(SandboxError::Other(format!(
                "cannot add gate to {plan_id}: stage is {:?}",
                p.stage
            )));
        }
        if p.gates.iter().any(|x| x.gate_id == gate.gate_id) {
            return Err(SandboxError::Other(format!(
                "gate id already present: {}",
                gate.gate_id
            )));
        }
        p.gates.push(gate);
        Ok(())
    }

    /// Update a gate's verdict (e.g., when async eval completes).
    pub fn set_gate_verdict(
        &self,
        plan_id: &str,
        gate_id: &str,
        verdict: PolicyVerdict,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        let gt = p
            .gates
            .iter_mut()
            .find(|x| x.gate_id == gate_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown gate {gate_id}")))?;
        gt.verdict = verdict;
        if let Some(r) = reason {
            gt.reason = Some(r);
        }
        Ok(())
    }

    /// Mark Reviewed by a reviewer (must differ from proposer).
    pub fn review(
        &self,
        plan_id: &str,
        reviewer: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        let reviewer = reviewer.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if reviewer == p.proposer {
            return Err(SandboxError::Other(format!(
                "reviewer {reviewer} must differ from proposer"
            )));
        }
        if !legal_transition(p.stage, PlanStage::Reviewed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Reviewed",
                p.stage
            )));
        }
        let when = at.into();
        let note = note.into();
        p.stage = PlanStage::Reviewed;
        p.reviewer = Some(reviewer.clone());
        p.events.push(PlanEvent {
            at: when,
            actor: reviewer,
            stage: PlanStage::Reviewed,
            note,
        });
        Ok(p.clone())
    }

    /// Approve. Approver must differ from proposer; gates must not block.
    pub fn approve(
        &self,
        plan_id: &str,
        approver: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        let approver = approver.into();
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if approver == p.proposer {
            return Err(SandboxError::Other(format!(
                "approver {approver} must differ from proposer"
            )));
        }
        if p.has_blocking_policy() {
            return Err(SandboxError::Other(format!(
                "cannot approve {plan_id}: blocking policy gate(s)"
            )));
        }
        if !legal_transition(p.stage, PlanStage::Approved) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Approved",
                p.stage
            )));
        }
        let when = at.into();
        let note = note.into();
        p.stage = PlanStage::Approved;
        p.approver = Some(approver.clone());
        p.events.push(PlanEvent {
            at: when,
            actor: approver,
            stage: PlanStage::Approved,
            note,
        });
        Ok(p.clone())
    }

    /// Begin Apply (Approved → Applying).
    pub fn begin_apply(
        &self,
        plan_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        self.simple_transition(plan_id, PlanStage::Applying, actor, at, "apply started")
    }

    /// Mark Applied.
    pub fn applied(
        &self,
        plan_id: &str,
        at: impl Into<String>,
        summary: Option<String>,
    ) -> SandboxResult<TerraformPlan> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if !legal_transition(p.stage, PlanStage::Applied) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Applied",
                p.stage
            )));
        }
        let when = at.into();
        p.stage = PlanStage::Applied;
        p.closed_at = Some(when.clone());
        if let Some(s) = summary.clone() {
            p.final_summary = Some(s);
        }
        p.events.push(PlanEvent {
            at: when,
            actor: "system".into(),
            stage: PlanStage::Applied,
            note: summary.unwrap_or_else(|| "applied".into()),
        });
        Ok(p.clone())
    }

    /// Mark Failed.
    pub fn failed(
        &self,
        plan_id: &str,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        self.simple_transition(plan_id, PlanStage::Failed, "system", at, reason)
    }

    /// Mark Discarded.
    pub fn discard(
        &self,
        plan_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        self.simple_transition(plan_id, PlanStage::Discarded, actor, at, reason)
    }

    /// Mark RolledBack.
    pub fn rollback(
        &self,
        plan_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        self.simple_transition(plan_id, PlanStage::RolledBack, actor, at, reason)
    }

    fn simple_transition(
        &self,
        plan_id: &str,
        new_stage: PlanStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<TerraformPlan> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        if !legal_transition(p.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                p.stage, new_stage
            )));
        }
        let when = at.into();
        p.stage = new_stage;
        match new_stage {
            PlanStage::Applying => {
                p.applying_at = Some(when.clone());
            }
            PlanStage::Applied
            | PlanStage::Failed
            | PlanStage::Discarded
            | PlanStage::RolledBack => {
                p.closed_at = Some(when.clone());
            }
            _ => {}
        }
        p.events.push(PlanEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(p.clone())
    }

    /// Set plan URI / artefact pointer.
    pub fn set_plan_uri(&self, plan_id: &str, uri: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        p.plan_uri = Some(uri.into());
        Ok(())
    }

    /// Set linked ticket.
    pub fn set_linked_ticket(
        &self,
        plan_id: &str,
        ticket: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        p.linked_ticket = Some(ticket.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, plan_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("terraform plan register poisoned".into()))?;
        let p = g
            .get_mut(plan_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown plan {plan_id}")))?;
        let tag = tag.into();
        if !p.tags.contains(&tag) {
            p.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, plan_id: &str) -> Option<TerraformPlan> {
        let g = self.inner.read().ok()?;
        g.get(plan_id).cloned()
    }

    /// All plans.
    pub fn all(&self) -> Vec<TerraformPlan> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Plans for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<TerraformPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.tenant_id == tenant_id)
            .collect()
    }

    /// Plans for a workspace.
    pub fn for_workspace(&self, workspace: &str) -> Vec<TerraformPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.workspace == workspace)
            .collect()
    }

    /// Plans by stage.
    pub fn by_stage(&self, stage: PlanStage) -> Vec<TerraformPlan> {
        self.all().into_iter().filter(|p| p.stage == stage).collect()
    }

    /// Plans currently applying.
    pub fn in_flight(&self) -> Vec<TerraformPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.stage.is_in_flight())
            .collect()
    }

    /// Plans containing destructive changes.
    pub fn destructive(&self) -> Vec<TerraformPlan> {
        self.all()
            .into_iter()
            .filter(|p| p.is_destructive())
            .collect()
    }

    /// Number of plans.
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

    fn plan(id: &str, proposer: &str) -> TerraformPlan {
        TerraformPlan::new(
            id,
            "tenant-a",
            "prod-us-east",
            "infra/network",
            format!("plan-{id}"),
            proposer,
            "abc123",
            "2025-04-01T00:00:00Z",
        )
    }

    fn change(addr: &str, kind: ResourceChangeKind) -> ResourceChange {
        ResourceChange {
            address: addr.into(),
            resource_type: "aws_instance".into(),
            kind,
            diff_summary: None,
        }
    }

    fn gate(id: &str, verdict: PolicyVerdict) -> PolicyGate {
        PolicyGate {
            gate_id: id.into(),
            name: format!("gate-{id}"),
            verdict,
            reason: None,
        }
    }

    #[test]
    fn register_and_get() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        assert!(r.get("p1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        let err = r.register(plan("p1", "alice")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn must_start_planned() {
        let mut p = plan("p1", "alice");
        p.stage = PlanStage::Approved;
        let r = TerraformPlanRegister::new();
        let err = r.register(p).unwrap_err();
        assert!(format!("{err}").contains("must start Planned"));
    }

    #[test]
    fn legal_transitions() {
        use PlanStage::*;
        assert!(legal_transition(Planned, Reviewed));
        assert!(legal_transition(Reviewed, Approved));
        assert!(legal_transition(Reviewed, Planned));
        assert!(legal_transition(Approved, Applying));
        assert!(legal_transition(Applying, Applied));
        assert!(legal_transition(Applying, Failed));
        assert!(legal_transition(Applied, RolledBack));
        assert!(legal_transition(Failed, Planned));
        // illegal
        assert!(!legal_transition(Planned, Approved));
        assert!(!legal_transition(Applied, Applying));
        assert!(!legal_transition(Discarded, Planned));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("aws_instance.web[0]", ResourceChangeKind::Create))
            .unwrap();
        r.add_gate("p1", gate("g1", PolicyVerdict::Pass)).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "looks good")
            .unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "approved")
            .unwrap();
        r.begin_apply("p1", "system", "2025-04-04T00:00:00Z").unwrap();
        let p = r
            .applied("p1", "2025-04-04T00:30:00Z", Some("clean apply".into()))
            .unwrap();
        assert_eq!(p.stage, PlanStage::Applied);
        assert!(p.stage.is_terminal());
        assert_eq!(p.events.len(), 4); // reviewed, approved, applying, applied
        assert_eq!(p.reviewer.as_deref(), Some("bob"));
        assert_eq!(p.approver.as_deref(), Some("carol"));
    }

    #[test]
    fn reviewer_must_differ_from_proposer() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        let err = r.review("p1", "alice", "2025-04-02T00:00:00Z", "n").unwrap_err();
        assert!(format!("{err}").contains("must differ from proposer"));
    }

    #[test]
    fn approver_must_differ_from_proposer() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("aws_instance.web[0]", ResourceChangeKind::Create))
            .unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        let err = r
            .approve("p1", "alice", "2025-04-03T00:00:00Z", "n")
            .unwrap_err();
        assert!(format!("{err}").contains("must differ from proposer"));
    }

    #[test]
    fn approve_blocked_by_policy_pending() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_gate("p1", gate("g1", PolicyVerdict::Pending)).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        let err = r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap_err();
        assert!(format!("{err}").contains("blocking policy"));
    }

    #[test]
    fn approve_blocked_by_hard_fail() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_gate("p1", gate("g1", PolicyVerdict::HardFail)).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        let err = r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap_err();
        assert!(format!("{err}").contains("blocking policy"));
    }

    #[test]
    fn approve_unblocked_by_override() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_gate("p1", gate("g1", PolicyVerdict::HardFail)).unwrap();
        r.set_gate_verdict("p1", "g1", PolicyVerdict::Override, Some("CFO sign-off".into()))
            .unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        assert_eq!(r.get("p1").unwrap().stage, PlanStage::Approved);
    }

    #[test]
    fn add_change_dedupes_address() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("aws_instance.web", ResourceChangeKind::Create))
            .unwrap();
        let err = r
            .add_change("p1", change("aws_instance.web", ResourceChangeKind::Update))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_change_after_planned_errors() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        let err = r
            .add_change("p1", change("aws_instance.web", ResourceChangeKind::Create))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add change"));
    }

    #[test]
    fn change_counts_correct() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("a1", ResourceChangeKind::Create)).unwrap();
        r.add_change("p1", change("a2", ResourceChangeKind::Create)).unwrap();
        r.add_change("p1", change("a3", ResourceChangeKind::Update)).unwrap();
        r.add_change("p1", change("a4", ResourceChangeKind::Replace)).unwrap();
        r.add_change("p1", change("a5", ResourceChangeKind::Destroy)).unwrap();
        r.add_change("p1", change("a6", ResourceChangeKind::Read)).unwrap();
        let p = r.get("p1").unwrap();
        let (c, u, rp, d) = p.change_counts();
        assert_eq!(c, 2);
        assert_eq!(u, 1);
        assert_eq!(rp, 1);
        assert_eq!(d, 1);
        assert!(p.is_destructive());
    }

    #[test]
    fn re_plan_after_review_feedback() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        // Send back to Planned to incorporate feedback
        r.simple_transition("p1", PlanStage::Planned, "alice", "2025-04-03T00:00:00Z", "re-plan")
            .unwrap();
        assert_eq!(r.get("p1").unwrap().stage, PlanStage::Planned);
    }

    #[test]
    fn re_plan_after_failure() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("aws_instance.web", ResourceChangeKind::Create))
            .unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        r.begin_apply("p1", "system", "2025-04-04T00:00:00Z").unwrap();
        r.failed("p1", "2025-04-04T00:30:00Z", "API limit").unwrap();
        // Failed → Planned (re-plan)
        r.simple_transition("p1", PlanStage::Planned, "alice", "2025-04-05T00:00:00Z", "retry")
            .unwrap();
        assert_eq!(r.get("p1").unwrap().stage, PlanStage::Planned);
    }

    #[test]
    fn rollback_after_applied() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("aws_instance.web", ResourceChangeKind::Create))
            .unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        r.begin_apply("p1", "system", "2025-04-04T00:00:00Z").unwrap();
        r.applied("p1", "2025-04-04T00:30:00Z", None).unwrap();
        let p = r
            .rollback("p1", "ops", "2025-04-04T01:00:00Z", "regression")
            .unwrap();
        assert_eq!(p.stage, PlanStage::RolledBack);
        assert!(p.stage.is_terminal());
    }

    #[test]
    fn discard_from_planned_or_reviewed_or_approved() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.discard("p1", "alice", "2025-04-02T00:00:00Z", "rebase").unwrap();
        assert_eq!(r.get("p1").unwrap().stage, PlanStage::Discarded);
        // Reviewed → Discarded
        r.register(plan("p2", "alice")).unwrap();
        r.review("p2", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.discard("p2", "bob", "2025-04-03T00:00:00Z", "scope changed").unwrap();
        // Approved → Discarded
        r.register(plan("p3", "alice")).unwrap();
        r.add_change("p3", change("a", ResourceChangeKind::Create)).unwrap();
        r.review("p3", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p3", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        r.discard("p3", "carol", "2025-04-04T00:00:00Z", "superseded").unwrap();
    }

    #[test]
    fn add_gate_after_apply_errors() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("a", ResourceChangeKind::Create)).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        r.begin_apply("p1", "system", "2025-04-04T00:00:00Z").unwrap();
        let err = r.add_gate("p1", gate("g1", PolicyVerdict::Pass)).unwrap_err();
        assert!(format!("{err}").contains("cannot add gate"));
    }

    #[test]
    fn add_gate_dedupes() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_gate("p1", gate("g1", PolicyVerdict::Pass)).unwrap();
        let err = r.add_gate("p1", gate("g1", PolicyVerdict::HardFail)).unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn set_gate_verdict_unknown_errors() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        let err = r
            .set_gate_verdict("p1", "missing", PolicyVerdict::Pass, None)
            .unwrap_err();
        assert!(format!("{err}").contains("unknown gate"));
    }

    #[test]
    fn set_uri_ticket_tag() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.set_plan_uri("p1", "s3://plans/p1.tfplan").unwrap();
        r.set_linked_ticket("p1", "INFRA-123").unwrap();
        r.add_tag("p1", "production").unwrap();
        r.add_tag("p1", "production").unwrap(); // dedupe
        let p = r.get("p1").unwrap();
        assert_eq!(p.plan_uri.as_deref(), Some("s3://plans/p1.tfplan"));
        assert_eq!(p.linked_ticket.as_deref(), Some("INFRA-123"));
        assert_eq!(p.tags, vec!["production"]);
    }

    #[test]
    fn unknown_plan_errors() {
        let r = TerraformPlanRegister::new();
        let err = r.set_plan_uri("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown plan"));
    }

    #[test]
    fn for_tenant_workspace_filters() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        let mut other = plan("p2", "alice");
        other.tenant_id = "tenant-b".into();
        other.workspace = "staging".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
        assert_eq!(r.for_workspace("prod-us-east").len(), 1);
        assert_eq!(r.for_workspace("staging").len(), 1);
    }

    #[test]
    fn in_flight_filter() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("a", ResourceChangeKind::Create)).unwrap();
        r.review("p1", "bob", "2025-04-02T00:00:00Z", "n").unwrap();
        r.approve("p1", "carol", "2025-04-03T00:00:00Z", "n").unwrap();
        r.begin_apply("p1", "system", "2025-04-04T00:00:00Z").unwrap();
        assert_eq!(r.in_flight().len(), 1);
    }

    #[test]
    fn destructive_filter() {
        let r = TerraformPlanRegister::new();
        r.register(plan("p1", "alice")).unwrap();
        r.add_change("p1", change("a1", ResourceChangeKind::Destroy)).unwrap();
        r.register(plan("p2", "alice")).unwrap();
        r.add_change("p2", change("a2", ResourceChangeKind::Create)).unwrap();
        let dest = r.destructive();
        assert_eq!(dest.len(), 1);
        assert_eq!(dest[0].plan_id, "p1");
    }

    #[test]
    fn verdict_helpers() {
        assert!(PolicyVerdict::Pending.blocks_approval());
        assert!(PolicyVerdict::HardFail.blocks_approval());
        assert!(!PolicyVerdict::Pass.blocks_approval());
        assert!(!PolicyVerdict::SoftFail.blocks_approval());
        assert!(!PolicyVerdict::Override.blocks_approval());
    }

    #[test]
    fn stage_helpers() {
        assert!(PlanStage::Applying.is_in_flight());
        for s in [
            PlanStage::Applied,
            PlanStage::Failed,
            PlanStage::Discarded,
            PlanStage::RolledBack,
        ] {
            assert!(s.is_terminal());
        }
        for s in [
            PlanStage::Planned,
            PlanStage::Reviewed,
            PlanStage::Approved,
            PlanStage::Applying,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = TerraformPlanRegister::new();
        assert_eq!(r.count(), 0);
        r.register(plan("p1", "alice")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn plan_serde() {
        let p = plan("p1", "alice");
        let j = serde_json::to_string(&p).unwrap();
        let back: TerraformPlan = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            PlanStage::Planned,
            PlanStage::Reviewed,
            PlanStage::Approved,
            PlanStage::Applying,
            PlanStage::Applied,
            PlanStage::Failed,
            PlanStage::Discarded,
            PlanStage::RolledBack,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<PlanStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for v in [
            PolicyVerdict::Pending,
            PolicyVerdict::Pass,
            PolicyVerdict::SoftFail,
            PolicyVerdict::HardFail,
            PolicyVerdict::Override,
        ] {
            assert_eq!(
                v,
                serde_json::from_str::<PolicyVerdict>(&serde_json::to_string(&v).unwrap()).unwrap()
            );
        }
        for k in [
            ResourceChangeKind::Create,
            ResourceChangeKind::Update,
            ResourceChangeKind::Replace,
            ResourceChangeKind::Destroy,
            ResourceChangeKind::Read,
        ] {
            assert_eq!(
                k,
                serde_json::from_str::<ResourceChangeKind>(&serde_json::to_string(&k).unwrap())
                    .unwrap()
            );
        }
    }
}
