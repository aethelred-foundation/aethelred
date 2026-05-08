//! Policy engine — fail-closed decision gate composition.
//!
//! The policy engine is the universal decision spine across every sector
//! sandbox. Sector crates declare a list of [`PolicyGate`]s; the engine
//! evaluates them in order and produces a [`Decision`]. Any required gate
//! that fails downgrades the overall decision to `FailClosed`. This is the
//! key safety property: sandboxes cannot accidentally *allow* a workflow
//! when a required gate fails.
//!
//! ## Composition
//!
//! Each sector composes its own gate list. For example, the finance crate
//! ships gates like `finance.model_approval`, `finance.human_authority`,
//! `finance.no_pii_on_chain`, `finance.evidence_integrity`, etc.

use crate::SandboxError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// High-level decision produced by the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// All required gates passed; workflow proceeds; seal is signable.
    Allow,
    /// At least one optional gate failed; workflow proceeds but reviewer is
    /// notified for follow-up.
    ReviewRequired,
    /// At least one required gate failed; workflow is blocked.
    FailClosed,
}

impl Decision {
    /// `true` for `Allow` only. `ReviewRequired` is *not* a pass — it is a
    /// soft-fail that still requires human follow-up.
    pub fn is_pass(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// `true` for `FailClosed`.
    pub fn is_blocked(self) -> bool {
        matches!(self, Self::FailClosed)
    }
}

/// A single policy gate. Gate authors typically use the convenience helpers
/// [`PolicyGate::required`] and [`PolicyGate::optional`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGate {
    /// Stable, sector-prefixed id (e.g., `"finance.human_authority"`).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Plain-English rule text.
    pub rule: String,
    /// `true` if a failure forces `FailClosed`. `false` makes it a soft gate.
    pub required: bool,
}

impl PolicyGate {
    /// Construct a required (fail-closed) gate.
    pub fn required(id: impl Into<String>, name: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            rule: rule.into(),
            required: true,
        }
    }

    /// Construct an optional (soft-fail / review-required) gate.
    pub fn optional(id: impl Into<String>, name: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            rule: rule.into(),
            required: false,
        }
    }
}

/// Per-gate evaluation outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutcome {
    /// Gate id.
    pub gate_id: String,
    /// Pass / fail.
    pub passed: bool,
    /// Optional reason (populated on failure).
    pub reason: Option<String>,
}

/// The policy engine. Parameterised by the sector's gate list.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    gates: Vec<PolicyGate>,
}

impl PolicyEngine {
    /// Construct a new engine over `gates`.
    pub fn new(gates: Vec<PolicyGate>) -> Self {
        Self { gates }
    }

    /// Borrow the gates.
    pub fn gates(&self) -> &[PolicyGate] {
        &self.gates
    }

    /// Add a new gate (typically used by sector crates extending a base).
    pub fn push(&mut self, gate: PolicyGate) {
        self.gates.push(gate);
    }

    /// Evaluate gates against a map of "fault" flags. A fault key matches a
    /// gate id; if present and `true`, the gate fails.
    ///
    /// For sector crates that need richer evaluation (e.g., schema checks,
    /// cross-field invariants), use [`PolicyEngine::evaluate_with`] instead.
    pub fn evaluate(&self, faults: &HashMap<String, bool>) -> (Decision, Vec<PolicyOutcome>) {
        let mut decision = Decision::Allow;
        let mut outcomes = Vec::with_capacity(self.gates.len());
        for gate in &self.gates {
            let failed = *faults.get(&gate.id).unwrap_or(&false);
            let outcome = PolicyOutcome {
                gate_id: gate.id.clone(),
                passed: !failed,
                reason: failed.then(|| format!("fault flag set for gate `{}`", gate.id)),
            };
            if failed {
                decision = if gate.required {
                    Decision::FailClosed
                } else if decision == Decision::Allow {
                    Decision::ReviewRequired
                } else {
                    decision
                };
            }
            outcomes.push(outcome);
        }
        (decision, outcomes)
    }

    /// Evaluate gates using a per-gate predicate. Returns the final decision
    /// and per-gate outcomes.
    ///
    /// Sector crates use this when each gate has its own structured predicate
    /// (e.g., "is the input policy class one of {synthetic, de_identified}?").
    pub fn evaluate_with<F>(&self, mut predicate: F) -> (Decision, Vec<PolicyOutcome>)
    where
        F: FnMut(&PolicyGate) -> Result<(), String>,
    {
        let mut decision = Decision::Allow;
        let mut outcomes = Vec::with_capacity(self.gates.len());
        for gate in &self.gates {
            let result = predicate(gate);
            let (passed, reason) = match result {
                Ok(_) => (true, None),
                Err(reason) => (false, Some(reason)),
            };
            let outcome = PolicyOutcome {
                gate_id: gate.id.clone(),
                passed,
                reason: reason.clone(),
            };
            if !passed {
                decision = if gate.required {
                    Decision::FailClosed
                } else if decision == Decision::Allow {
                    Decision::ReviewRequired
                } else {
                    decision
                };
            }
            outcomes.push(outcome);
        }
        (decision, outcomes)
    }

    /// Convert a `Decision::FailClosed` into a `SandboxError::PolicyDenied`
    /// that names the first failing gate. Use this when the sector workflow
    /// wants to short-circuit on the first denial.
    pub fn first_denial(&self, outcomes: &[PolicyOutcome]) -> Option<SandboxError> {
        outcomes
            .iter()
            .find(|o| !o.passed)
            .map(|o| SandboxError::policy(&o.gate_id, o.reason.clone().unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> PolicyEngine {
        PolicyEngine::new(vec![
            PolicyGate::required("test.required_a", "Required A", "rule a"),
            PolicyGate::required("test.required_b", "Required B", "rule b"),
            PolicyGate::optional("test.optional_c", "Optional C", "rule c"),
        ])
    }

    #[test]
    fn no_faults_allows() {
        let (d, _) = engine().evaluate(&HashMap::new());
        assert_eq!(d, Decision::Allow);
    }

    #[test]
    fn required_fault_fails_closed() {
        let mut faults = HashMap::new();
        faults.insert("test.required_a".to_string(), true);
        let (d, outcomes) = engine().evaluate(&faults);
        assert_eq!(d, Decision::FailClosed);
        assert!(!outcomes.iter().find(|o| o.gate_id == "test.required_a").unwrap().passed);
    }

    #[test]
    fn optional_fault_only_review_required() {
        let mut faults = HashMap::new();
        faults.insert("test.optional_c".to_string(), true);
        let (d, _) = engine().evaluate(&faults);
        assert_eq!(d, Decision::ReviewRequired);
    }

    #[test]
    fn required_overrides_optional() {
        let mut faults = HashMap::new();
        faults.insert("test.optional_c".to_string(), true);
        faults.insert("test.required_a".to_string(), true);
        let (d, _) = engine().evaluate(&faults);
        assert_eq!(d, Decision::FailClosed);
    }

    #[test]
    fn first_denial_reports_first_failing_gate() {
        let mut faults = HashMap::new();
        faults.insert("test.required_a".to_string(), true);
        faults.insert("test.required_b".to_string(), true);
        let e = engine();
        let (_, outcomes) = e.evaluate(&faults);
        let err = e.first_denial(&outcomes).unwrap();
        match err {
            SandboxError::PolicyDenied { policy_gate, .. } => assert_eq!(policy_gate, "test.required_a"),
            _ => panic!("expected PolicyDenied"),
        }
    }
}
