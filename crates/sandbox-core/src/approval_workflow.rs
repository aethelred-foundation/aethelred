//! Multi-step approval workflow engine.
//!
//! v0.2 [`ApprovalRecord`] is a single-approver attachment. Production
//! workflows often require multi-step approvals: a credit decision goes
//! to (1) underwriter → (2) manager IF amount > X → (3) compliance IF
//! adverse outcome. This module implements the state machine.
//!
//! ## What we ship
//!
//! - [`ApprovalStep`] — one step in the workflow (sequential / parallel /
//!   M-of-N gating).
//! - [`ApprovalWorkflow`] — declarative DAG of steps.
//! - [`ApprovalInstance`] — runtime state of one in-flight approval.
//! - [`ApprovalAction`] — `Approve` / `Reject` / `Escalate` / `Abstain`.
//! - [`ApprovalState`] — `Pending` / `InProgress` / `Approved` /
//!   `Rejected` / `Expired`.
//!
//! ## Composition rules
//!
//! - **Sequential**: each step must complete before the next begins.
//! - **Parallel**: all steps in a parallel group must complete (any
//!   rejection terminates the whole instance).
//! - **M-of-N**: any M of the N approvers in the step must approve.
//!
//! ## What this gives you
//!
//! Compliance teams declare workflows declaratively (JSON-friendly)
//! instead of hard-coding state-machine logic in workflow code.

use crate::seal::ApprovalRecord;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ApprovalAction
// =============================================================================

/// One approver's decision on a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAction {
    /// Approve.
    Approve,
    /// Reject.
    Reject,
    /// Escalate to next step / parent.
    Escalate,
    /// Abstain (counts as neither approve nor reject for M-of-N).
    Abstain,
}

// =============================================================================
// ApprovalState
// =============================================================================

/// Lifecycle state of an approval instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Not yet started.
    Pending,
    /// At least one step in flight.
    InProgress,
    /// All steps approved.
    Approved,
    /// At least one step rejected (or M-of-N failed).
    Rejected,
    /// Past deadline before resolving.
    Expired,
}

impl ApprovalState {
    /// `true` if terminal (no further actions accepted).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Approved | Self::Rejected | Self::Expired)
    }
}

// =============================================================================
// ApprovalStep
// =============================================================================

/// Step composition mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum StepMode {
    /// One specific approver must approve.
    Single {
        /// Required approver role / id.
        approver: String,
    },
    /// All approvers in the list must approve.
    All {
        /// Approver list.
        approvers: Vec<String>,
    },
    /// Any one approver in the list approves.
    Any {
        /// Approver list.
        approvers: Vec<String>,
    },
    /// M of N approvers must approve.
    MofN {
        /// Approver list (size N).
        approvers: Vec<String>,
        /// Threshold M.
        threshold: u32,
    },
}

/// One step in the workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalStep {
    /// Stable id (e.g., `"underwriter_review"`).
    pub id: String,
    /// Human-readable label.
    pub label: String,
    /// Composition mode.
    pub mode: StepMode,
    /// Optional condition: this step is required only if predicate
    /// matches. For now the predicate is a free-form string; production
    /// deployments evaluate it against context tags.
    pub condition: Option<String>,
    /// Maximum time to complete (seconds). `None` = no limit.
    pub deadline_seconds: Option<u64>,
}

impl ApprovalStep {
    /// New single-approver step.
    pub fn single(id: impl Into<String>, label: impl Into<String>, approver: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            mode: StepMode::Single {
                approver: approver.into(),
            },
            condition: None,
            deadline_seconds: None,
        }
    }

    /// New M-of-N step.
    pub fn m_of_n(
        id: impl Into<String>,
        label: impl Into<String>,
        approvers: Vec<String>,
        threshold: u32,
    ) -> SandboxResult<Self> {
        if threshold == 0 || threshold as usize > approvers.len() {
            return Err(SandboxError::config(format!(
                "M-of-N threshold {threshold} not in 1..={}",
                approvers.len()
            )));
        }
        Ok(Self {
            id: id.into(),
            label: label.into(),
            mode: StepMode::MofN {
                approvers,
                threshold,
            },
            condition: None,
            deadline_seconds: None,
        })
    }

    /// Add a deadline.
    pub fn with_deadline(mut self, secs: u64) -> Self {
        self.deadline_seconds = Some(secs);
        self
    }

    /// Set condition.
    pub fn when(mut self, condition: impl Into<String>) -> Self {
        self.condition = Some(condition.into());
        self
    }
}

// =============================================================================
// ApprovalWorkflow
// =============================================================================

/// Declarative workflow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalWorkflow {
    /// Stable workflow id.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Steps in sequential order.
    pub steps: Vec<ApprovalStep>,
}

impl ApprovalWorkflow {
    /// New workflow.
    pub fn new(id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            steps: Vec::new(),
        }
    }

    /// Append a step.
    pub fn add_step(mut self, step: ApprovalStep) -> Self {
        self.steps.push(step);
        self
    }

    /// Validate.
    pub fn validate(&self) -> SandboxResult<()> {
        if self.id.is_empty() {
            return Err(SandboxError::config("workflow id is empty"));
        }
        if self.steps.is_empty() {
            return Err(SandboxError::config("workflow has no steps"));
        }
        let mut seen = std::collections::HashSet::new();
        for s in &self.steps {
            if !seen.insert(&s.id) {
                return Err(SandboxError::config(format!(
                    "duplicate step id: {}",
                    s.id
                )));
            }
        }
        Ok(())
    }
}

// =============================================================================
// ApprovalInstance
// =============================================================================

/// Per-step runtime state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StepState {
    /// Step id.
    pub step_id: String,
    /// Decisions captured so far.
    pub decisions: Vec<ApprovalDecision>,
    /// Step-level state.
    pub state: ApprovalState,
}

/// One approver's decision on one step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalDecision {
    /// Approver id (matches the step's `approvers`).
    pub approver: String,
    /// Action.
    pub action: ApprovalAction,
    /// RFC 3339 timestamp.
    pub at: String,
    /// Optional reason / comment.
    pub reason: Option<String>,
}

/// Runtime state of one in-flight approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalInstance {
    /// Instance id.
    pub instance_id: Uuid,
    /// Workflow being run.
    pub workflow: ApprovalWorkflow,
    /// Tenant id.
    pub tenant_id: String,
    /// Subject ref (e.g., the seal id this approval relates to).
    pub subject_ref: String,
    /// RFC 3339 creation timestamp.
    pub started_at: String,
    /// Per-step state.
    pub step_states: Vec<StepState>,
    /// Global state.
    pub state: ApprovalState,
    /// Active step index (0 .. steps.len()).
    pub current_step: usize,
    /// Optional context tags (used by step `condition`s).
    pub context: BTreeMap<String, String>,
}

impl ApprovalInstance {
    /// Start a new instance.
    pub fn start(
        workflow: ApprovalWorkflow,
        tenant_id: impl Into<String>,
        subject_ref: impl Into<String>,
    ) -> SandboxResult<Self> {
        workflow.validate()?;
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let step_states: Vec<StepState> = workflow
            .steps
            .iter()
            .map(|s| StepState {
                step_id: s.id.clone(),
                decisions: Vec::new(),
                state: ApprovalState::Pending,
            })
            .collect();
        let mut inst = Self {
            instance_id: Uuid::now_v7(),
            workflow,
            tenant_id: tenant_id.into(),
            subject_ref: subject_ref.into(),
            started_at: now,
            step_states,
            state: ApprovalState::InProgress,
            current_step: 0,
            context: BTreeMap::new(),
        };
        inst.advance_to_first_required_step();
        Ok(inst)
    }

    /// Add a context tag. Re-evaluates skipped steps with the new context.
    pub fn with_context(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.context.insert(k.into(), v.into());
        // Reset to the start and re-advance — context can re-enable
        // previously skipped steps.
        for ss in &mut self.step_states {
            if ss.decisions.is_empty() {
                ss.state = ApprovalState::Pending;
            }
        }
        self.current_step = 0;
        self.state = ApprovalState::InProgress;
        self.advance_to_first_required_step();
        self
    }

    /// Skip steps whose `condition` doesn't match the context. Marks them
    /// `Approved` (skipped) so the instance can advance.
    fn advance_to_first_required_step(&mut self) {
        while self.current_step < self.workflow.steps.len() {
            let s = &self.workflow.steps[self.current_step];
            if let Some(cond) = &s.condition {
                let matches = self
                    .context
                    .iter()
                    .any(|(k, v)| {
                        let pair = format!("{}={}", k, v);
                        cond == &pair || cond == k
                    });
                if !matches {
                    self.step_states[self.current_step].state = ApprovalState::Approved;
                    self.current_step += 1;
                    continue;
                }
            }
            self.step_states[self.current_step].state = ApprovalState::InProgress;
            break;
        }
        if self.current_step >= self.workflow.steps.len() {
            self.state = ApprovalState::Approved;
        }
    }

    /// Submit a decision.
    pub fn submit(
        &mut self,
        approver: impl Into<String>,
        action: ApprovalAction,
        reason: Option<String>,
    ) -> SandboxResult<()> {
        if self.state.is_terminal() {
            return Err(SandboxError::Other(format!(
                "instance is terminal: {:?}",
                self.state
            )));
        }
        if self.current_step >= self.workflow.steps.len() {
            return Err(SandboxError::Other("no current step".into()));
        }
        let approver = approver.into();
        let step = self.workflow.steps[self.current_step].clone();
        let step_state = &mut self.step_states[self.current_step];
        // Check approver is in the step's approver list.
        let allowed: bool = match &step.mode {
            StepMode::Single { approver: a } => *a == approver,
            StepMode::All { approvers }
            | StepMode::Any { approvers }
            | StepMode::MofN { approvers, .. } => approvers.contains(&approver),
        };
        if !allowed {
            return Err(SandboxError::Other(format!(
                "approver {approver} not authorised for step {}",
                step.id
            )));
        }
        // Check approver hasn't already decided.
        if step_state
            .decisions
            .iter()
            .any(|d| d.approver == approver)
        {
            return Err(SandboxError::Other(format!(
                "approver {approver} already decided on step {}",
                step.id
            )));
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        step_state.decisions.push(ApprovalDecision {
            approver,
            action,
            at: now,
            reason,
        });
        // Evaluate the step.
        self.evaluate_current_step();
        Ok(())
    }

    fn evaluate_current_step(&mut self) {
        let step = &self.workflow.steps[self.current_step];
        let step_state = &mut self.step_states[self.current_step];
        let approvals = step_state
            .decisions
            .iter()
            .filter(|d| d.action == ApprovalAction::Approve)
            .count();
        let rejections = step_state
            .decisions
            .iter()
            .filter(|d| d.action == ApprovalAction::Reject)
            .count();
        match &step.mode {
            StepMode::Single { .. } => {
                if rejections > 0 {
                    step_state.state = ApprovalState::Rejected;
                    self.state = ApprovalState::Rejected;
                } else if approvals > 0 {
                    step_state.state = ApprovalState::Approved;
                    self.advance_step();
                }
            }
            StepMode::All { approvers } => {
                if rejections > 0 {
                    step_state.state = ApprovalState::Rejected;
                    self.state = ApprovalState::Rejected;
                } else if approvals == approvers.len() {
                    step_state.state = ApprovalState::Approved;
                    self.advance_step();
                }
            }
            StepMode::Any { .. } => {
                if approvals > 0 {
                    step_state.state = ApprovalState::Approved;
                    self.advance_step();
                } else if rejections > 0 {
                    // For Any, any rejection is just one negative — only
                    // reject the step if all have rejected.
                    if let StepMode::Any { approvers } = &step.mode {
                        if rejections == approvers.len() {
                            step_state.state = ApprovalState::Rejected;
                            self.state = ApprovalState::Rejected;
                        }
                    }
                }
            }
            StepMode::MofN {
                approvers,
                threshold,
            } => {
                if approvals >= *threshold as usize {
                    step_state.state = ApprovalState::Approved;
                    self.advance_step();
                } else if rejections > approvers.len() - *threshold as usize {
                    // Even if remaining approve, can't hit M.
                    step_state.state = ApprovalState::Rejected;
                    self.state = ApprovalState::Rejected;
                }
            }
        }
    }

    fn advance_step(&mut self) {
        self.current_step += 1;
        self.advance_to_first_required_step();
    }

    /// Mark the instance expired (e.g., past a deadline).
    pub fn expire(&mut self) {
        if !self.state.is_terminal() {
            self.state = ApprovalState::Expired;
        }
    }

    /// Convert all completed decisions into [`ApprovalRecord`]s for
    /// attachment to a [`crate::seal::DigitalSeal`].
    pub fn to_approval_records(&self) -> Vec<ApprovalRecord> {
        let mut out = Vec::new();
        for ss in &self.step_states {
            for d in &ss.decisions {
                let timestamp = OffsetDateTime::parse(
                    &d.at,
                    &time::format_description::well_known::Rfc3339,
                )
                .unwrap_or_else(|_| OffsetDateTime::now_utc());
                out.push(ApprovalRecord {
                    approver_ref: d.approver.clone(),
                    role: ss.step_id.clone(),
                    decision: format!("{:?}", d.action).to_lowercase(),
                    reason_class: d.reason.clone(),
                    timestamp,
                    signature_hex: None,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn single_step_wf() -> ApprovalWorkflow {
        ApprovalWorkflow::new("credit_review", "Credit Review")
            .add_step(ApprovalStep::single(
                "underwriter",
                "Underwriter approval",
                "alice",
            ))
    }

    fn two_step_wf() -> ApprovalWorkflow {
        ApprovalWorkflow::new("credit_review", "Credit Review")
            .add_step(ApprovalStep::single(
                "underwriter",
                "Underwriter",
                "alice",
            ))
            .add_step(ApprovalStep::single(
                "manager",
                "Manager",
                "bob",
            ))
    }

    #[test]
    fn single_step_approve_finalises() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn single_step_reject_terminates() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Reject, Some("bad".into())).unwrap();
        assert_eq!(inst.state, ApprovalState::Rejected);
    }

    #[test]
    fn unauthorised_approver_rejected() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        let r = inst.submit("eve", ApprovalAction::Approve, None);
        assert!(r.is_err());
    }

    #[test]
    fn duplicate_approver_decision_rejected() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Abstain, None).unwrap();
        let r = inst.submit("alice", ApprovalAction::Approve, None);
        assert!(r.is_err());
    }

    #[test]
    fn two_step_sequential() {
        let mut inst = ApprovalInstance::start(two_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Approve, None).unwrap();
        // Now on step 2.
        assert_eq!(inst.current_step, 1);
        inst.submit("bob", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn two_step_first_reject_terminates() {
        let mut inst = ApprovalInstance::start(two_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Reject, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Rejected);
    }

    #[test]
    fn m_of_n_threshold_met() {
        let step = ApprovalStep::m_of_n(
            "compliance",
            "M-of-N",
            vec!["a".into(), "b".into(), "c".into()],
            2,
        )
        .unwrap();
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Approve, None).unwrap();
        // Not yet — only 1 of 2.
        assert_eq!(inst.state, ApprovalState::InProgress);
        inst.submit("b", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn m_of_n_too_many_rejects_terminates() {
        let step = ApprovalStep::m_of_n(
            "compliance",
            "M-of-N",
            vec!["a".into(), "b".into(), "c".into()],
            2,
        )
        .unwrap();
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Reject, None).unwrap();
        inst.submit("b", ApprovalAction::Reject, None).unwrap();
        // Even if c approves, only 1 of 2 → instance is rejected.
        assert_eq!(inst.state, ApprovalState::Rejected);
    }

    #[test]
    fn all_step_requires_all_approvals() {
        let step = ApprovalStep {
            id: "all".into(),
            label: "All".into(),
            mode: StepMode::All {
                approvers: vec!["a".into(), "b".into()],
            },
            condition: None,
            deadline_seconds: None,
        };
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::InProgress);
        inst.submit("b", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn any_step_first_approval_terminates() {
        let step = ApprovalStep {
            id: "any".into(),
            label: "Any".into(),
            mode: StepMode::Any {
                approvers: vec!["a".into(), "b".into()],
            },
            condition: None,
            deadline_seconds: None,
        };
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn any_step_all_rejects_terminates() {
        let step = ApprovalStep {
            id: "any".into(),
            label: "Any".into(),
            mode: StepMode::Any {
                approvers: vec!["a".into(), "b".into()],
            },
            condition: None,
            deadline_seconds: None,
        };
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Reject, None).unwrap();
        assert_eq!(inst.state, ApprovalState::InProgress);
        inst.submit("b", ApprovalAction::Reject, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Rejected);
    }

    #[test]
    fn workflow_validate_rejects_empty_id() {
        let wf = ApprovalWorkflow::new("", "X").add_step(ApprovalStep::single("s1", "S1", "a"));
        assert!(wf.validate().is_err());
    }

    #[test]
    fn workflow_validate_rejects_no_steps() {
        let wf = ApprovalWorkflow::new("x", "X");
        assert!(wf.validate().is_err());
    }

    #[test]
    fn workflow_validate_rejects_duplicate_step_ids() {
        let wf = ApprovalWorkflow::new("x", "X")
            .add_step(ApprovalStep::single("s", "S", "a"))
            .add_step(ApprovalStep::single("s", "S", "b"));
        assert!(wf.validate().is_err());
    }

    #[test]
    fn m_of_n_zero_threshold_rejected() {
        let r = ApprovalStep::m_of_n("x", "X", vec!["a".into()], 0);
        assert!(r.is_err());
    }

    #[test]
    fn m_of_n_threshold_above_n_rejected() {
        let r = ApprovalStep::m_of_n("x", "X", vec!["a".into()], 5);
        assert!(r.is_err());
    }

    #[test]
    fn instance_terminal_blocks_further_submissions() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Approve, None).unwrap();
        let r = inst.submit("alice", ApprovalAction::Approve, None);
        assert!(r.is_err());
    }

    #[test]
    fn expire_marks_terminal() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.expire();
        assert_eq!(inst.state, ApprovalState::Expired);
    }

    #[test]
    fn expire_after_terminal_is_noop() {
        let mut inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        inst.submit("alice", ApprovalAction::Approve, None).unwrap();
        inst.expire();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn condition_skips_step() {
        let wf = ApprovalWorkflow::new("x", "X")
            .add_step(
                ApprovalStep::single("only_if_amount_high", "X", "alice")
                    .when("amount=high"),
            )
            .add_step(ApprovalStep::single("manager", "M", "bob"));
        let mut inst = ApprovalInstance::start(wf, "FAB", "seal-1")
            .unwrap()
            .with_context("amount", "low");
        inst.advance_to_first_required_step();
        // First step skipped, current is step 1 (manager).
        assert_eq!(inst.current_step, 1);
        inst.submit("bob", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn to_approval_records_returns_one_per_decision() {
        let mut inst = ApprovalInstance::start(two_step_wf(), "FAB", "s").unwrap();
        inst.submit("alice", ApprovalAction::Approve, Some("ok".into()))
            .unwrap();
        inst.submit("bob", ApprovalAction::Approve, None).unwrap();
        let records = inst.to_approval_records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].approver_ref, "alice");
        assert_eq!(records[1].approver_ref, "bob");
    }

    #[test]
    fn approval_action_serde_round_trip() {
        let a = ApprovalAction::Approve;
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "\"approve\"");
    }

    #[test]
    fn approval_state_terminal_check() {
        assert!(ApprovalState::Approved.is_terminal());
        assert!(ApprovalState::Rejected.is_terminal());
        assert!(ApprovalState::Expired.is_terminal());
        assert!(!ApprovalState::Pending.is_terminal());
        assert!(!ApprovalState::InProgress.is_terminal());
    }

    #[test]
    fn workflow_serde_round_trip() {
        let wf = two_step_wf();
        let j = serde_json::to_string(&wf).unwrap();
        let p: ApprovalWorkflow = serde_json::from_str(&j).unwrap();
        assert_eq!(p, wf);
    }

    #[test]
    fn instance_serde_round_trip() {
        let inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1").unwrap();
        let j = serde_json::to_string(&inst).unwrap();
        let p: ApprovalInstance = serde_json::from_str(&j).unwrap();
        assert_eq!(p.tenant_id, inst.tenant_id);
    }

    #[test]
    fn instance_with_context_records_tags() {
        let inst = ApprovalInstance::start(single_step_wf(), "FAB", "seal-1")
            .unwrap()
            .with_context("session", "s1");
        assert_eq!(inst.context.get("session").map(String::as_str), Some("s1"));
    }

    #[test]
    fn step_with_deadline_recorded() {
        let s = ApprovalStep::single("s", "S", "a").with_deadline(3600);
        assert_eq!(s.deadline_seconds, Some(3600));
    }

    #[test]
    fn condition_step_runs_when_matching() {
        let wf = ApprovalWorkflow::new("x", "X").add_step(
            ApprovalStep::single("conditional", "C", "alice").when("amount=high"),
        );
        let mut inst = ApprovalInstance::start(wf, "FAB", "s")
            .unwrap()
            .with_context("amount", "high");
        inst.advance_to_first_required_step();
        assert_eq!(inst.current_step, 0);
        inst.submit("alice", ApprovalAction::Approve, None).unwrap();
        assert_eq!(inst.state, ApprovalState::Approved);
    }

    #[test]
    fn step_states_track_per_step() {
        let inst = ApprovalInstance::start(two_step_wf(), "FAB", "s").unwrap();
        assert_eq!(inst.step_states.len(), 2);
    }

    #[test]
    fn multiple_decisions_recorded_in_step_state() {
        let step = ApprovalStep::m_of_n(
            "x",
            "X",
            vec!["a".into(), "b".into(), "c".into()],
            2,
        )
        .unwrap();
        let wf = ApprovalWorkflow::new("x", "X").add_step(step);
        let mut inst = ApprovalInstance::start(wf, "FAB", "s").unwrap();
        inst.submit("a", ApprovalAction::Approve, None).unwrap();
        inst.submit("b", ApprovalAction::Approve, None).unwrap();
        let s = &inst.step_states[0];
        assert_eq!(s.decisions.len(), 2);
    }
}
