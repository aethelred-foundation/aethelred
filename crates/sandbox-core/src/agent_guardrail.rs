//! Per-agent action guardrail registry.
//!
//! Each [`AgentGuardrail`] specifies — for one named agent — the set of
//! tools it is allowed to invoke, hard limits on action shape (max output
//! tokens, max tool calls per turn), prohibited content categories, the
//! tenant scope, and an optional human-approval gate (which tools require
//! human-in-the-loop sign-off before execution).
//!
//! At runtime, the agent runtime calls [`AgentGuardrailRegistry::evaluate`]
//! with a candidate action and gets back a [`GuardrailDecision`]:
//!
//! - `Allow` — proceed.
//! - `RequireApproval(reason)` — pause, route to human review queue.
//! - `Deny(reason)` — fail-closed, log, and surface to operator.
//!
//! Maps to NIST AI RMF MANAGE-2.4 (action constraint), EU AI Act Art 14
//! (human oversight), and emerging "agent action policy" guidance from
//! OWASP / MITRE ATLAS.
//!
//! Distinct from [`crate::policy`] / [`crate::policy_dsl`] (which gate
//! seal'd events) and [`crate::tool_invocation`] (which logs the actual
//! invocation): this module is the **pre-flight policy** that decides
//! whether the invocation is permitted at all.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// GuardrailDecision
// =============================================================================

/// Outcome of evaluating an agent action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind", content = "reason")]
pub enum GuardrailDecision {
    /// Action permitted.
    Allow,
    /// Action requires explicit human approval before execution.
    RequireApproval(String),
    /// Action denied.
    Deny(String),
}

impl GuardrailDecision {
    /// True if Allow.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// True if Deny.
    pub fn is_deny(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// True if RequireApproval.
    pub fn is_approval_required(&self) -> bool {
        matches!(self, Self::RequireApproval(_))
    }

    /// Reason text, if any.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::RequireApproval(r) | Self::Deny(r) => Some(r.as_str()),
        }
    }
}

// =============================================================================
// ProposedAction
// =============================================================================

/// One action the agent wants to take.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProposedAction {
    /// Tool / function name.
    pub tool: String,
    /// Optional content category labels the runtime detected on this
    /// action's payload (e.g., "pii", "self_harm", "code_execution").
    pub content_categories: Vec<String>,
    /// Estimated output token count (or 0 if not known).
    pub output_tokens: u64,
    /// How many tool calls (including this one) the agent has made this
    /// turn so far.
    pub tool_calls_this_turn: u64,
    /// Free-form metadata.
    pub metadata: Option<String>,
}

impl ProposedAction {
    /// New `ProposedAction` with no content categories and unknown tokens.
    pub fn new(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            content_categories: Vec::new(),
            output_tokens: 0,
            tool_calls_this_turn: 0,
            metadata: None,
        }
    }

    /// Builder: attach a content category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.content_categories.push(category.into());
        self
    }

    /// Builder: set output token estimate.
    pub fn with_output_tokens(mut self, tokens: u64) -> Self {
        self.output_tokens = tokens;
        self
    }

    /// Builder: set turn-counter.
    pub fn with_tool_calls_this_turn(mut self, calls: u64) -> Self {
        self.tool_calls_this_turn = calls;
        self
    }
}

// =============================================================================
// AgentGuardrail
// =============================================================================

/// Guardrail policy for one named agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentGuardrail {
    /// Stable agent id.
    pub agent_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Display name.
    pub name: String,
    /// Tools the agent may invoke. Empty = none allowed.
    pub allowed_tools: Vec<String>,
    /// Tools that require human approval before execution.
    pub approval_required_tools: Vec<String>,
    /// Content categories that are prohibited entirely.
    pub prohibited_categories: Vec<String>,
    /// Maximum output tokens per action; 0 = unlimited.
    pub max_output_tokens: u64,
    /// Maximum tool calls per agent turn; 0 = unlimited.
    pub max_tool_calls_per_turn: u64,
    /// Free-form tags ("safety-critical", "low-risk").
    pub tags: Vec<String>,
    /// True if the guardrail is active.
    pub enabled: bool,
    /// RFC 3339 — created.
    pub created_at: String,
    /// RFC 3339 — last updated.
    pub last_updated_at: String,
}

impl AgentGuardrail {
    /// Construct a new guardrail.
    pub fn new(
        agent_id: impl Into<String>,
        tenant_id: impl Into<String>,
        name: impl Into<String>,
        created_at: impl Into<String>,
    ) -> Self {
        let when = created_at.into();
        Self {
            agent_id: agent_id.into(),
            tenant_id: tenant_id.into(),
            name: name.into(),
            allowed_tools: Vec::new(),
            approval_required_tools: Vec::new(),
            prohibited_categories: Vec::new(),
            max_output_tokens: 0,
            max_tool_calls_per_turn: 0,
            tags: Vec::new(),
            enabled: true,
            created_at: when.clone(),
            last_updated_at: when,
        }
    }

    /// Evaluate `action` against this guardrail.
    pub fn evaluate(&self, action: &ProposedAction) -> GuardrailDecision {
        if !self.enabled {
            return GuardrailDecision::Allow;
        }
        // Tool allowlist
        if !self.allowed_tools.iter().any(|t| t == &action.tool) {
            return GuardrailDecision::Deny(format!("tool '{}' not allowed", action.tool));
        }
        // Prohibited content categories — Deny supersedes everything.
        for cat in &action.content_categories {
            if self.prohibited_categories.iter().any(|p| p == cat) {
                return GuardrailDecision::Deny(format!(
                    "prohibited content category: {cat}"
                ));
            }
        }
        // Output token cap.
        if self.max_output_tokens > 0 && action.output_tokens > self.max_output_tokens {
            return GuardrailDecision::Deny(format!(
                "output {} tokens exceeds cap {}",
                action.output_tokens, self.max_output_tokens
            ));
        }
        // Tool-calls-per-turn cap.
        if self.max_tool_calls_per_turn > 0
            && action.tool_calls_this_turn > self.max_tool_calls_per_turn
        {
            return GuardrailDecision::Deny(format!(
                "{} tool calls this turn exceeds cap {}",
                action.tool_calls_this_turn, self.max_tool_calls_per_turn
            ));
        }
        // Approval gate.
        if self
            .approval_required_tools
            .iter()
            .any(|t| t == &action.tool)
        {
            return GuardrailDecision::RequireApproval(format!(
                "tool '{}' requires human approval",
                action.tool
            ));
        }
        GuardrailDecision::Allow
    }
}

// =============================================================================
// AgentGuardrailRegistry
// =============================================================================

/// Thread-safe registry of agent guardrails.
#[derive(Debug, Default)]
pub struct AgentGuardrailRegistry {
    inner: RwLock<HashMap<String, AgentGuardrail>>,
}

impl AgentGuardrailRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new guardrail.
    pub fn register(&self, gr: AgentGuardrail) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        if g.contains_key(&gr.agent_id) {
            return Err(SandboxError::Other(format!(
                "guardrail already registered: {}",
                gr.agent_id
            )));
        }
        g.insert(gr.agent_id.clone(), gr);
        Ok(())
    }

    /// Add an allowed tool (deduplicated).
    pub fn allow_tool(
        &self,
        agent_id: &str,
        tool: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        let tool = tool.into();
        if !gr.allowed_tools.contains(&tool) {
            gr.allowed_tools.push(tool);
        }
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Mark a tool as requiring approval (deduplicated).
    pub fn require_approval(
        &self,
        agent_id: &str,
        tool: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        let tool = tool.into();
        if !gr.approval_required_tools.contains(&tool) {
            gr.approval_required_tools.push(tool);
        }
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Add a prohibited content category.
    pub fn prohibit_category(
        &self,
        agent_id: &str,
        category: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        let cat = category.into();
        if !gr.prohibited_categories.contains(&cat) {
            gr.prohibited_categories.push(cat);
        }
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Set output-token cap.
    pub fn set_max_output_tokens(
        &self,
        agent_id: &str,
        cap: u64,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        gr.max_output_tokens = cap;
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Set tool-calls-per-turn cap.
    pub fn set_max_tool_calls_per_turn(
        &self,
        agent_id: &str,
        cap: u64,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        gr.max_tool_calls_per_turn = cap;
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Toggle the guardrail.
    pub fn set_enabled(
        &self,
        agent_id: &str,
        enabled: bool,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        gr.enabled = enabled;
        gr.last_updated_at = at.into();
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, agent_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("agent guardrail registry poisoned".into()))?;
        let gr = g
            .get_mut(agent_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown agent {agent_id}")))?;
        let tag = tag.into();
        if !gr.tags.contains(&tag) {
            gr.tags.push(tag);
        }
        Ok(())
    }

    /// Evaluate a candidate action. If the agent has no registered
    /// guardrail, returns `Deny` (fail-closed).
    pub fn evaluate(
        &self,
        agent_id: &str,
        action: &ProposedAction,
    ) -> GuardrailDecision {
        match self.get(agent_id) {
            Some(gr) => gr.evaluate(action),
            None => GuardrailDecision::Deny(format!(
                "no guardrail registered for agent {agent_id}"
            )),
        }
    }

    /// Look up.
    pub fn get(&self, agent_id: &str) -> Option<AgentGuardrail> {
        let g = self.inner.read().ok()?;
        g.get(agent_id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<AgentGuardrail> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<AgentGuardrail> {
        self.all()
            .into_iter()
            .filter(|g| g.tenant_id == tenant_id)
            .collect()
    }

    /// Count.
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

    fn gr(id: &str) -> AgentGuardrail {
        AgentGuardrail::new(id, "tenant-a", format!("agent-{id}"), "2025-05-01T00:00:00Z")
    }

    fn act(tool: &str) -> ProposedAction {
        ProposedAction::new(tool)
    }

    #[test]
    fn register_and_get() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        assert!(r.get("a1").is_some());
    }

    #[test]
    fn duplicate_register_errors() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        let err = r.register(gr("a1")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn no_guardrail_denies() {
        let r = AgentGuardrailRegistry::new();
        let d = r.evaluate("ghost", &act("foo"));
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("no guardrail"));
    }

    #[test]
    fn empty_allowlist_denies() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        let d = r.evaluate("a1", &act("search"));
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("not allowed"));
    }

    #[test]
    fn allowed_tool_passes() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "search", "2025-05-02T00:00:00Z").unwrap();
        let d = r.evaluate("a1", &act("search"));
        assert!(d.is_allow());
    }

    #[test]
    fn approval_required_tool() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "execute_code", "2025-05-02T00:00:00Z").unwrap();
        r.require_approval("a1", "execute_code", "2025-05-02T00:00:00Z")
            .unwrap();
        let d = r.evaluate("a1", &act("execute_code"));
        assert!(d.is_approval_required());
        assert!(d.reason().unwrap().contains("requires human approval"));
    }

    #[test]
    fn prohibited_category_denies() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "respond", "2025-05-02T00:00:00Z").unwrap();
        r.prohibit_category("a1", "self_harm", "2025-05-02T00:00:00Z")
            .unwrap();
        let d = r.evaluate("a1", &act("respond").with_category("self_harm"));
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("prohibited content category"));
    }

    #[test]
    fn output_token_cap_denies() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "respond", "2025-05-02T00:00:00Z").unwrap();
        r.set_max_output_tokens("a1", 1000, "2025-05-02T00:00:00Z")
            .unwrap();
        let d = r.evaluate("a1", &act("respond").with_output_tokens(2000));
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("exceeds cap"));
    }

    #[test]
    fn output_token_cap_zero_means_unlimited() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "respond", "2025-05-02T00:00:00Z").unwrap();
        // cap stays 0
        let d = r.evaluate("a1", &act("respond").with_output_tokens(99999));
        assert!(d.is_allow());
    }

    #[test]
    fn tool_calls_per_turn_cap_denies() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "search", "2025-05-02T00:00:00Z").unwrap();
        r.set_max_tool_calls_per_turn("a1", 5, "2025-05-02T00:00:00Z")
            .unwrap();
        let d = r.evaluate("a1", &act("search").with_tool_calls_this_turn(6));
        assert!(d.is_deny());
        assert!(d.reason().unwrap().contains("tool calls this turn"));
    }

    #[test]
    fn disabled_guardrail_allows_everything() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.set_enabled("a1", false, "2025-05-02T00:00:00Z").unwrap();
        // No tools allow-listed but disabled → still allow
        let d = r.evaluate("a1", &act("anything"));
        assert!(d.is_allow());
    }

    #[test]
    fn deny_supersedes_approval() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "execute_code", "2025-05-02T00:00:00Z").unwrap();
        r.require_approval("a1", "execute_code", "2025-05-02T00:00:00Z")
            .unwrap();
        r.prohibit_category("a1", "rm_rf", "2025-05-02T00:00:00Z")
            .unwrap();
        let d = r.evaluate("a1", &act("execute_code").with_category("rm_rf"));
        assert!(d.is_deny());
    }

    #[test]
    fn allow_tool_dedupes() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "search", "2025-05-02T00:00:00Z").unwrap();
        r.allow_tool("a1", "search", "2025-05-02T00:00:00Z").unwrap();
        assert_eq!(r.get("a1").unwrap().allowed_tools, vec!["search"]);
    }

    #[test]
    fn require_approval_dedupes() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.allow_tool("a1", "x", "2025-05-02T00:00:00Z").unwrap();
        r.require_approval("a1", "x", "2025-05-02T00:00:00Z").unwrap();
        r.require_approval("a1", "x", "2025-05-02T00:00:00Z").unwrap();
        assert_eq!(r.get("a1").unwrap().approval_required_tools, vec!["x"]);
    }

    #[test]
    fn prohibit_category_dedupes() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.prohibit_category("a1", "pii", "2025-05-02T00:00:00Z").unwrap();
        r.prohibit_category("a1", "pii", "2025-05-02T00:00:00Z").unwrap();
        assert_eq!(r.get("a1").unwrap().prohibited_categories, vec!["pii"]);
    }

    #[test]
    fn add_tag_dedupes() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a1")).unwrap();
        r.add_tag("a1", "safety-critical").unwrap();
        r.add_tag("a1", "safety-critical").unwrap();
        assert_eq!(r.get("a1").unwrap().tags, vec!["safety-critical"]);
    }

    #[test]
    fn unknown_agent_errors() {
        let r = AgentGuardrailRegistry::new();
        let err = r.allow_tool("nope", "x", "2025-05-02T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown agent"));
    }

    #[test]
    fn for_tenant_filters() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a")).unwrap();
        let mut other = gr("b");
        other.tenant_id = "tenant-b".into();
        r.register(other).unwrap();
        assert_eq!(r.for_tenant("tenant-a").len(), 1);
        assert_eq!(r.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn count_tracks() {
        let r = AgentGuardrailRegistry::new();
        assert_eq!(r.count(), 0);
        r.register(gr("a")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn decision_helpers() {
        let a = GuardrailDecision::Allow;
        assert!(a.is_allow());
        assert!(a.reason().is_none());
        let d = GuardrailDecision::Deny("x".into());
        assert!(d.is_deny());
        assert_eq!(d.reason(), Some("x"));
        let r = GuardrailDecision::RequireApproval("y".into());
        assert!(r.is_approval_required());
        assert_eq!(r.reason(), Some("y"));
    }

    #[test]
    fn last_updated_advances() {
        let r = AgentGuardrailRegistry::new();
        r.register(gr("a")).unwrap();
        assert_eq!(r.get("a").unwrap().last_updated_at, "2025-05-01T00:00:00Z");
        r.allow_tool("a", "search", "2025-05-04T00:00:00Z").unwrap();
        assert_eq!(r.get("a").unwrap().last_updated_at, "2025-05-04T00:00:00Z");
    }

    #[test]
    fn proposed_action_builders() {
        let a = ProposedAction::new("search")
            .with_category("pii")
            .with_output_tokens(100)
            .with_tool_calls_this_turn(2);
        assert_eq!(a.tool, "search");
        assert_eq!(a.content_categories, vec!["pii"]);
        assert_eq!(a.output_tokens, 100);
        assert_eq!(a.tool_calls_this_turn, 2);
    }

    #[test]
    fn guardrail_serde() {
        let g = gr("a");
        let j = serde_json::to_string(&g).unwrap();
        let back: AgentGuardrail = serde_json::from_str(&j).unwrap();
        assert_eq!(g, back);
    }

    #[test]
    fn proposed_action_serde() {
        let a = ProposedAction::new("search").with_category("pii");
        let j = serde_json::to_string(&a).unwrap();
        let back: ProposedAction = serde_json::from_str(&j).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn decision_serde() {
        for d in [
            GuardrailDecision::Allow,
            GuardrailDecision::Deny("x".into()),
            GuardrailDecision::RequireApproval("y".into()),
        ] {
            let j = serde_json::to_string(&d).unwrap();
            let back: GuardrailDecision = serde_json::from_str(&j).unwrap();
            assert_eq!(d, back);
        }
    }
}
