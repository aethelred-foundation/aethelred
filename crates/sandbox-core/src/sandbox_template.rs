//! Per-customer sandbox deployment templates.
//!
//! When a new customer onboards, the operator picks a [`SandboxTemplate`]
//! that bundles: which sectors are enabled, default policies, retention
//! defaults, KEK provider, and feature-flag defaults. This module is the
//! catalog. New customers are provisioned via
//! [`SandboxTemplate::instantiate_for`] which produces a deterministic
//! [`SandboxBlueprint`] the deployment system uses.

use crate::seal::RetentionClass;
use crate::sector::Sector;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// SandboxTemplate
// =============================================================================

/// One template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxTemplate {
    /// Stable id (e.g. `"banking-tier1"`).
    pub template_id: String,
    /// Display name.
    pub name: String,
    /// Sectors enabled.
    pub sectors: Vec<Sector>,
    /// Default policy ids to install.
    pub default_policy_ids: Vec<String>,
    /// Default workflow templates to install.
    pub default_workflow_template_ids: Vec<String>,
    /// Default retention class for seals.
    pub default_retention: RetentionClass,
    /// Per-flag default (`flag_id` → boolean).
    pub feature_flag_defaults: HashMap<String, bool>,
    /// `true` if BYOK is required (customer must supply KEK before activation).
    pub requires_byok: bool,
    /// `true` if SSO is required.
    pub requires_sso: bool,
    /// Free-text description.
    pub description: String,
    /// RFC 3339 created.
    pub created_at: String,
}

// =============================================================================
// SandboxBlueprint
// =============================================================================

/// Customer-specific deployment blueprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SandboxBlueprint {
    /// Tenant id.
    pub tenant_id: String,
    /// Source template id.
    pub template_id: String,
    /// Resolved sectors.
    pub sectors: Vec<Sector>,
    /// Resolved policy ids.
    pub policy_ids: Vec<String>,
    /// Resolved workflow template ids.
    pub workflow_template_ids: Vec<String>,
    /// Retention default.
    pub default_retention: RetentionClass,
    /// Feature flag defaults.
    pub feature_flag_defaults: HashMap<String, bool>,
    /// Required setup steps (BYOK, SSO).
    pub setup_steps_required: Vec<String>,
    /// RFC 3339 generated.
    pub generated_at: String,
}

// =============================================================================
// TemplateCatalog
// =============================================================================

#[derive(Default)]
struct State {
    templates: HashMap<String, SandboxTemplate>,
}

/// Catalog.
pub struct TemplateCatalog {
    state: RwLock<State>,
}

impl Default for TemplateCatalog {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for TemplateCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TemplateCatalog")
            .field("templates", &self.len())
            .finish()
    }
}

impl TemplateCatalog {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a template.
    pub fn register(&self, t: SandboxTemplate) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("template catalog poisoned".into()))?;
        if g.templates.contains_key(&t.template_id) {
            return Err(SandboxError::Other(format!(
                "template {} already registered",
                t.template_id
            )));
        }
        if t.sectors.is_empty() {
            return Err(SandboxError::Other(
                "template must enable at least one sector".into(),
            ));
        }
        g.templates.insert(t.template_id.clone(), t);
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<SandboxTemplate> {
        self.state.read().ok()?.templates.get(id).cloned()
    }

    /// All templates.
    pub fn all(&self) -> Vec<SandboxTemplate> {
        self.state
            .read()
            .map(|g| g.templates.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Templates enabling a sector.
    pub fn for_sector(&self, sector: Sector) -> Vec<SandboxTemplate> {
        self.all()
            .into_iter()
            .filter(|t| t.sectors.contains(&sector))
            .collect()
    }

    /// Instantiate a template for a tenant.
    pub fn instantiate_for(
        &self,
        template_id: &str,
        tenant_id: impl Into<String>,
    ) -> SandboxResult<SandboxBlueprint> {
        let t = self
            .get(template_id)
            .ok_or_else(|| SandboxError::Other(format!("template {} not found", template_id)))?;
        let mut steps = Vec::new();
        if t.requires_byok {
            steps.push("provision-byok".into());
        }
        if t.requires_sso {
            steps.push("configure-sso".into());
        }
        Ok(SandboxBlueprint {
            tenant_id: tenant_id.into(),
            template_id: t.template_id,
            sectors: t.sectors,
            policy_ids: t.default_policy_ids,
            workflow_template_ids: t.default_workflow_template_ids,
            default_retention: t.default_retention,
            feature_flag_defaults: t.feature_flag_defaults,
            setup_steps_required: steps,
            generated_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.templates.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// TemplateBuilder
// =============================================================================

/// Builder for [`SandboxTemplate`].
pub struct TemplateBuilder {
    template_id: String,
    name: String,
    sectors: Vec<Sector>,
    default_policy_ids: Vec<String>,
    default_workflow_template_ids: Vec<String>,
    default_retention: RetentionClass,
    feature_flag_defaults: HashMap<String, bool>,
    requires_byok: bool,
    requires_sso: bool,
    description: String,
}

impl TemplateBuilder {
    /// New.
    pub fn new(
        template_id: impl Into<String>,
        name: impl Into<String>,
        default_retention: RetentionClass,
    ) -> Self {
        Self {
            template_id: template_id.into(),
            name: name.into(),
            sectors: Vec::new(),
            default_policy_ids: Vec::new(),
            default_workflow_template_ids: Vec::new(),
            default_retention,
            feature_flag_defaults: HashMap::new(),
            requires_byok: false,
            requires_sso: false,
            description: String::new(),
        }
    }
    /// Add a sector.
    pub fn sector(mut self, s: Sector) -> Self {
        if !self.sectors.contains(&s) {
            self.sectors.push(s);
        }
        self
    }
    /// Add a policy.
    pub fn policy(mut self, p: impl Into<String>) -> Self {
        self.default_policy_ids.push(p.into());
        self
    }
    /// Add a workflow template.
    pub fn workflow(mut self, w: impl Into<String>) -> Self {
        self.default_workflow_template_ids.push(w.into());
        self
    }
    /// Set feature flag default.
    pub fn flag(mut self, id: impl Into<String>, value: bool) -> Self {
        self.feature_flag_defaults.insert(id.into(), value);
        self
    }
    /// Require BYOK.
    pub fn require_byok(mut self) -> Self {
        self.requires_byok = true;
        self
    }
    /// Require SSO.
    pub fn require_sso(mut self) -> Self {
        self.requires_sso = true;
        self
    }
    /// Description.
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }
    /// Build.
    pub fn build(self) -> SandboxResult<SandboxTemplate> {
        if self.template_id.trim().is_empty() {
            return Err(SandboxError::Other("template_id required".into()));
        }
        Ok(SandboxTemplate {
            template_id: self.template_id,
            name: self.name,
            sectors: self.sectors,
            default_policy_ids: self.default_policy_ids,
            default_workflow_template_ids: self.default_workflow_template_ids,
            default_retention: self.default_retention,
            feature_flag_defaults: self.feature_flag_defaults,
            requires_byok: self.requires_byok,
            requires_sso: self.requires_sso,
            description: self.description,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template() -> SandboxTemplate {
        TemplateBuilder::new("banking-tier1", "Banking Tier 1", RetentionClass::SevenYears)
            .sector(Sector::Finance)
            .policy("po_kyc_v3")
            .policy("po_aml_v2")
            .workflow("wf_loan")
            .flag("new-credit-model", true)
            .require_byok()
            .require_sso()
            .description("Top-tier bank deployment")
            .build()
            .unwrap()
    }

    #[test]
    fn build_creates_template() {
        let t = template();
        assert_eq!(t.template_id, "banking-tier1");
        assert!(t.requires_byok && t.requires_sso);
        assert_eq!(t.sectors.len(), 1);
    }

    #[test]
    fn empty_id_errors() {
        let r = TemplateBuilder::new("", "x", RetentionClass::OneYear).build();
        assert!(r.is_err());
    }

    #[test]
    fn sector_dedupes() {
        let t = TemplateBuilder::new("x", "X", RetentionClass::OneYear)
            .sector(Sector::Finance)
            .sector(Sector::Finance)
            .build()
            .unwrap();
        assert_eq!(t.sectors.len(), 1);
    }

    #[test]
    fn register_succeeds() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        assert!(c.register(template()).is_err());
    }

    #[test]
    fn empty_sectors_errors() {
        let c = TemplateCatalog::new();
        let mut t = template();
        t.sectors.clear();
        assert!(c.register(t).is_err());
    }

    #[test]
    fn for_sector_filters() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let mut t2 = template();
        t2.template_id = "research".into();
        t2.sectors = vec![Sector::Research];
        c.register(t2).unwrap();
        assert_eq!(c.for_sector(Sector::Finance).len(), 1);
        assert_eq!(c.for_sector(Sector::Research).len(), 1);
    }

    #[test]
    fn instantiate_creates_blueprint() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        assert_eq!(bp.tenant_id, "FAB");
        assert!(bp.setup_steps_required.contains(&"provision-byok".to_string()));
        assert!(bp.setup_steps_required.contains(&"configure-sso".to_string()));
    }

    #[test]
    fn instantiate_unknown_errors() {
        let c = TemplateCatalog::new();
        assert!(c.instantiate_for("ghost", "FAB").is_err());
    }

    #[test]
    fn instantiate_no_setup_steps_when_not_required() {
        let c = TemplateCatalog::new();
        let mut t = template();
        t.requires_byok = false;
        t.requires_sso = false;
        c.register(t).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        assert!(bp.setup_steps_required.is_empty());
    }

    #[test]
    fn instantiate_carries_policies() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        assert_eq!(bp.policy_ids.len(), 2);
    }

    #[test]
    fn flag_defaults_carried() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        assert_eq!(
            bp.feature_flag_defaults.get("new-credit-model"),
            Some(&true)
        );
    }

    #[test]
    fn template_serde() {
        let t = template();
        let j = serde_json::to_string(&t).unwrap();
        let p: SandboxTemplate = serde_json::from_str(&j).unwrap();
        assert_eq!(p, t);
    }

    #[test]
    fn blueprint_serde() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        let j = serde_json::to_string(&bp).unwrap();
        let p: SandboxBlueprint = serde_json::from_str(&j).unwrap();
        assert_eq!(p, bp);
    }

    #[test]
    fn count_tracks() {
        let c = TemplateCatalog::new();
        assert!(c.is_empty());
        c.register(template()).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn lookup_unknown_none() {
        let c = TemplateCatalog::new();
        assert!(c.get("ghost").is_none());
    }

    #[test]
    fn all_returns_all() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let mut t2 = template();
        t2.template_id = "x".into();
        c.register(t2).unwrap();
        assert_eq!(c.all().len(), 2);
    }

    #[test]
    fn retention_carried_through() {
        let c = TemplateCatalog::new();
        c.register(template()).unwrap();
        let bp = c.instantiate_for("banking-tier1", "FAB").unwrap();
        assert_eq!(bp.default_retention, RetentionClass::SevenYears);
    }

    #[test]
    fn require_byok_only() {
        let t = TemplateBuilder::new("x", "X", RetentionClass::OneYear)
            .sector(Sector::Finance)
            .require_byok()
            .build()
            .unwrap();
        let c = TemplateCatalog::new();
        c.register(t).unwrap();
        let bp = c.instantiate_for("x", "FAB").unwrap();
        assert!(bp.setup_steps_required.contains(&"provision-byok".to_string()));
        assert!(!bp.setup_steps_required.contains(&"configure-sso".to_string()));
    }

    #[test]
    fn workflows_carried() {
        let t = TemplateBuilder::new("x", "X", RetentionClass::OneYear)
            .sector(Sector::Finance)
            .workflow("wf-a")
            .workflow("wf-b")
            .build()
            .unwrap();
        let c = TemplateCatalog::new();
        c.register(t).unwrap();
        let bp = c.instantiate_for("x", "FAB").unwrap();
        assert_eq!(bp.workflow_template_ids.len(), 2);
    }

    #[test]
    fn many_templates_isolated() {
        let c = TemplateCatalog::new();
        for i in 0..10 {
            let t = TemplateBuilder::new(format!("t{i}"), "X", RetentionClass::OneYear)
                .sector(Sector::Finance)
                .build()
                .unwrap();
            c.register(t).unwrap();
        }
        assert_eq!(c.len(), 10);
    }
}
