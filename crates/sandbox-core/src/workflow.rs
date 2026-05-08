//! Universal `Workflow` trait — the contract every sector workflow implements.
//!
//! A workflow takes a typed `Input`, runs the sector-specific logic
//! (policy gates, evidence emission, optional connector consumption), and
//! produces a typed `Output`. The output for production workflows is
//! ultimately sealed into a [`crate::seal::DigitalSeal`] and pushed to the
//! [`crate::evidence::EvidenceLog`].
//!
//! ## Why a trait, not a closure?
//!
//! Sector workflows have rich *associated types* — a credit decision has
//! different input shape from a genomics inference. Encoding these as
//! associated types lets callers store typed sandboxes without erasure
//! while still allowing sector crates to expose convenience functions.

use crate::policy::PolicyEngine;
use crate::sector::Sector;
use crate::SandboxResult;
use serde::{Deserialize, Serialize};

/// Class of workflow event — used for stats, dashboards, and the `event_type`
/// field on the [`crate::seal::DigitalSeal`].
///
/// Sector crates typically use `Custom("clinical_inference")` etc.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowEventClass {
    /// Inference / model run (e.g., a credit-risk score computed).
    Inference,
    /// Decision (e.g., approve / reject / escalate).
    Decision,
    /// Action (e.g., AI agent calling a tool).
    Action,
    /// Release (e.g., open-source model release pack).
    Release,
    /// Sector-specific custom class.
    Custom(String),
}

impl WorkflowEventClass {
    /// String form for logs.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inference => "inference",
            Self::Decision => "decision",
            Self::Action => "action",
            Self::Release => "release",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Per-workflow event metadata.
///
/// Sector crates populate this on the way into the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowEvent {
    /// Workflow id (e.g., `"credit_decision"`).
    pub workflow_id: String,
    /// Event class.
    pub class: WorkflowEventClass,
    /// Tenant id.
    pub tenant_id: String,
    /// Jurisdiction tag (e.g., `"AE-CBUAE"`, `"EU"`, `"US"`).
    pub jurisdiction_tag: String,
}

/// Context passed to a workflow on every run.
///
/// Provides the workflow read-only access to the policy engine and the
/// sandbox configuration. Workflows do **not** mutate the engine — that is
/// owned by the [`crate::Sandbox`].
pub struct WorkflowContext<'a> {
    /// The policy engine the workflow should consult.
    pub policy: &'a PolicyEngine,
    /// The sandbox tenant id (e.g., `"FAB"`, `"M42"`).
    pub tenant_id: &'a str,
    /// Optional fault flags to inject (used by adversarial tests).
    pub faults: &'a std::collections::HashMap<String, bool>,
}

/// The universal workflow contract. Sector crates implement this for each
/// production workflow they support.
///
/// ## Type-safety
///
/// The associated `Input` and `Output` types are sector-specific structs
/// (e.g., `CreditDecision` and `CreditSeal`). This means callers cannot
/// accidentally pass a healthcare input into a finance workflow.
pub trait Workflow {
    /// The typed input.
    type Input;
    /// The typed output.
    type Output;

    /// Sector this workflow belongs to.
    fn sector(&self) -> Sector;

    /// Stable workflow id (e.g., `"credit_decision"`, `"genomics_inference"`).
    fn workflow_id(&self) -> &str;

    /// Run the workflow against `input`. Sector crates implement the full
    /// pipeline here: parse input, evaluate policy gates via `ctx.policy`,
    /// produce typed output (which sector crates typically pass to a typed
    /// `seal_*` method on the sector sandbox).
    fn run(&self, ctx: WorkflowContext<'_>, input: Self::Input) -> SandboxResult<Self::Output>;
}
