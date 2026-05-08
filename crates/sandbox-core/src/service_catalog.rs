//! Service catalog — internal developer portal / lightweight CMDB.
//!
//! Distinct from [`crate::service_map`] (the *dependency graph* used for
//! blast-radius queries), this module is the **service registry**: every
//! service has an owner, lifecycle state, documentation links, the on-call
//! schedule it is bound to, and the SLOs it commits to. It is the
//! single source of truth answering "who owns this and where do I read
//! about it?"
//!
//! Maps to ITIL CMDB and Backstage-style developer portals. Lifecycle
//! transitions follow `Proposed → Alpha → Beta → Ga → Deprecated → Retired`
//! with `Retired` terminal.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// LifecycleStage
// =============================================================================

/// Service lifecycle stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    /// Approved on the roadmap, no code yet.
    Proposed,
    /// Internal alpha; breaking changes expected.
    Alpha,
    /// Externally available beta; backwards compat best-effort.
    Beta,
    /// Generally available production service.
    Ga,
    /// Deprecation announced; replacement available.
    Deprecated,
    /// Service decommissioned; metadata retained for audit.
    Retired,
}

impl LifecycleStage {
    /// True if the service is still serving traffic.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Beta | Self::Ga | Self::Deprecated)
    }

    /// True if the service is fully decommissioned.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Retired)
    }
}

// =============================================================================
// ComplianceScope
// =============================================================================

/// Compliance regimes the service is in scope for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceScope {
    /// SOC 2 Type II
    Soc2,
    /// ISO 27001
    Iso27001,
    /// HIPAA
    Hipaa,
    /// PCI-DSS
    PciDss,
    /// FedRAMP
    Fedramp,
    /// GDPR
    Gdpr,
    /// CCPA / CPRA
    Ccpa,
}

// =============================================================================
// Link
// =============================================================================

/// Named link attached to a service entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Link {
    /// Display label.
    pub label: String,
    /// URL or URI.
    pub url: String,
}

// =============================================================================
// SloBinding
// =============================================================================

/// Reference to a registered SLO that this service commits to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SloBinding {
    /// SLO id (matches [`crate::slo_tracking::SloId`]).
    pub slo_id: String,
    /// Short description.
    pub label: String,
}

// =============================================================================
// ServiceEntry
// =============================================================================

/// One catalogued service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceEntry {
    /// Stable id (e.g., "billing-api", "fraud-scoring").
    pub service_id: String,
    /// Tenant scope (use "global" for platform-wide services).
    pub tenant_id: String,
    /// Human-friendly name.
    pub display_name: String,
    /// One-line summary.
    pub summary: String,
    /// Owning team / squad.
    pub owner_team: String,
    /// Owner contact (email or pager).
    pub owner_contact: String,
    /// On-call schedule id ([`crate::on_call_schedule::Schedule`]).
    pub on_call_schedule_id: Option<String>,
    /// Current lifecycle stage.
    pub lifecycle: LifecycleStage,
    /// Source repository.
    pub repository: Option<String>,
    /// Documentation links.
    pub links: Vec<Link>,
    /// Compliance scope.
    pub compliance: Vec<ComplianceScope>,
    /// SLOs this service commits to.
    pub slos: Vec<SloBinding>,
    /// Free-form tags ("revenue", "regulated", "experimental").
    pub tags: Vec<String>,
    /// RFC 3339 — registered.
    pub registered_at: String,
    /// RFC 3339 — last updated.
    pub last_updated_at: String,
}

impl ServiceEntry {
    /// Construct a new service entry in the `Proposed` stage.
    pub fn new(
        service_id: impl Into<String>,
        tenant_id: impl Into<String>,
        display_name: impl Into<String>,
        summary: impl Into<String>,
        owner_team: impl Into<String>,
        owner_contact: impl Into<String>,
        registered_at: impl Into<String>,
    ) -> Self {
        let when = registered_at.into();
        Self {
            service_id: service_id.into(),
            tenant_id: tenant_id.into(),
            display_name: display_name.into(),
            summary: summary.into(),
            owner_team: owner_team.into(),
            owner_contact: owner_contact.into(),
            on_call_schedule_id: None,
            lifecycle: LifecycleStage::Proposed,
            repository: None,
            links: Vec::new(),
            compliance: Vec::new(),
            slos: Vec::new(),
            tags: Vec::new(),
            registered_at: when.clone(),
            last_updated_at: when,
        }
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_lifecycle(from: LifecycleStage, to: LifecycleStage) -> bool {
    use LifecycleStage::*;
    match (from, to) {
        (Proposed, Alpha)
        | (Proposed, Retired)
        | (Alpha, Beta)
        | (Alpha, Retired)
        | (Beta, Ga)
        | (Beta, Deprecated)
        | (Beta, Retired)
        | (Ga, Deprecated)
        | (Ga, Retired)
        | (Deprecated, Retired) => true,
        _ => false,
    }
}

// =============================================================================
// ServiceCatalog
// =============================================================================

/// Thread-safe service catalog.
#[derive(Debug, Default)]
pub struct ServiceCatalog {
    inner: RwLock<HashMap<String, ServiceEntry>>,
}

impl ServiceCatalog {
    /// New empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new service.
    pub fn register(&self, entry: ServiceEntry) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        if g.contains_key(&entry.service_id) {
            return Err(SandboxError::Other(format!(
                "service already registered: {}",
                entry.service_id
            )));
        }
        g.insert(entry.service_id.clone(), entry);
        Ok(())
    }

    /// Apply a lifecycle transition. `at` is RFC 3339; sets last_updated_at.
    pub fn transition(
        &self,
        service_id: &str,
        new_stage: LifecycleStage,
        at: impl Into<String>,
    ) -> SandboxResult<ServiceEntry> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        if !legal_lifecycle(s.lifecycle, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal lifecycle transition {:?} -> {:?}",
                s.lifecycle, new_stage
            )));
        }
        s.lifecycle = new_stage;
        s.last_updated_at = at.into();
        Ok(s.clone())
    }

    /// Set the bound on-call schedule.
    pub fn set_on_call(
        &self,
        service_id: &str,
        schedule_id: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        s.on_call_schedule_id = Some(schedule_id.into());
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Set the source repository.
    pub fn set_repository(
        &self,
        service_id: &str,
        repo: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        s.repository = Some(repo.into());
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Append a documentation link.
    pub fn add_link(
        &self,
        service_id: &str,
        link: Link,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        s.links.push(link);
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Add a compliance scope (deduplicated).
    pub fn add_compliance(
        &self,
        service_id: &str,
        scope: ComplianceScope,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        if !s.compliance.contains(&scope) {
            s.compliance.push(scope);
        }
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Add an SLO binding (deduplicated by slo_id).
    pub fn add_slo(
        &self,
        service_id: &str,
        slo: SloBinding,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        if !s.slos.iter().any(|b| b.slo_id == slo.slo_id) {
            s.slos.push(slo);
        }
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(
        &self,
        service_id: &str,
        tag: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("service catalog poisoned".into()))?;
        let s = g
            .get_mut(service_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown service {service_id}")))?;
        let tag = tag.into();
        if !s.tags.contains(&tag) {
            s.tags.push(tag);
        }
        s.last_updated_at = at.into();
        Ok(())
    }

    /// Look up a service.
    pub fn get(&self, service_id: &str) -> Option<ServiceEntry> {
        let g = self.inner.read().ok()?;
        g.get(service_id).cloned()
    }

    /// All services.
    pub fn all(&self) -> Vec<ServiceEntry> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Services owned by a team.
    pub fn for_team(&self, team: &str) -> Vec<ServiceEntry> {
        self.all()
            .into_iter()
            .filter(|s| s.owner_team == team)
            .collect()
    }

    /// Services in a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<ServiceEntry> {
        self.all()
            .into_iter()
            .filter(|s| s.tenant_id == tenant_id)
            .collect()
    }

    /// Services at a given lifecycle stage.
    pub fn by_lifecycle(&self, stage: LifecycleStage) -> Vec<ServiceEntry> {
        self.all()
            .into_iter()
            .filter(|s| s.lifecycle == stage)
            .collect()
    }

    /// Services in a given compliance scope.
    pub fn in_compliance_scope(&self, scope: ComplianceScope) -> Vec<ServiceEntry> {
        self.all()
            .into_iter()
            .filter(|s| s.compliance.contains(&scope))
            .collect()
    }

    /// Services with no on-call binding (operational risk).
    pub fn missing_on_call(&self) -> Vec<ServiceEntry> {
        self.all()
            .into_iter()
            .filter(|s| s.lifecycle.is_live() && s.on_call_schedule_id.is_none())
            .collect()
    }

    /// Number of registered services.
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

    fn entry(id: &str) -> ServiceEntry {
        ServiceEntry::new(
            id,
            "tenant-a",
            format!("Service {id}"),
            "summary",
            "platform",
            "platform@example.test",
            "2025-05-01T00:00:00Z",
        )
    }

    #[test]
    fn register_and_get() {
        let c = ServiceCatalog::new();
        c.register(entry("billing-api")).unwrap();
        let s = c.get("billing-api").unwrap();
        assert_eq!(s.lifecycle, LifecycleStage::Proposed);
        assert!(s.on_call_schedule_id.is_none());
    }

    #[test]
    fn duplicate_register_errors() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        let err = c.register(entry("a")).unwrap_err();
        assert!(format!("{err}").contains("already registered"));
    }

    #[test]
    fn legal_lifecycle_table() {
        use LifecycleStage::*;
        assert!(legal_lifecycle(Proposed, Alpha));
        assert!(legal_lifecycle(Alpha, Beta));
        assert!(legal_lifecycle(Beta, Ga));
        assert!(legal_lifecycle(Ga, Deprecated));
        assert!(legal_lifecycle(Deprecated, Retired));
        assert!(legal_lifecycle(Beta, Retired));
        // Illegal moves
        assert!(!legal_lifecycle(Proposed, Ga));
        assert!(!legal_lifecycle(Ga, Beta));
        assert!(!legal_lifecycle(Retired, Ga));
        assert!(!legal_lifecycle(Deprecated, Ga));
    }

    #[test]
    fn happy_path_lifecycle() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.transition("a", LifecycleStage::Alpha, "2025-05-02T00:00:00Z")
            .unwrap();
        c.transition("a", LifecycleStage::Beta, "2025-05-03T00:00:00Z")
            .unwrap();
        c.transition("a", LifecycleStage::Ga, "2025-05-04T00:00:00Z")
            .unwrap();
        let s = c.get("a").unwrap();
        assert_eq!(s.lifecycle, LifecycleStage::Ga);
        assert_eq!(s.last_updated_at, "2025-05-04T00:00:00Z");
    }

    #[test]
    fn illegal_transition_errors() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        let err = c
            .transition("a", LifecycleStage::Ga, "2025-05-02T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("illegal lifecycle transition"));
    }

    #[test]
    fn unknown_service_errors() {
        let c = ServiceCatalog::new();
        let err = c
            .transition("nope", LifecycleStage::Alpha, "2025-05-02T00:00:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("unknown service"));
    }

    #[test]
    fn set_on_call_set_repo() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.set_on_call("a", "sre", "2025-05-02T00:00:00Z").unwrap();
        c.set_repository("a", "git@host:org/a", "2025-05-02T00:00:00Z")
            .unwrap();
        let s = c.get("a").unwrap();
        assert_eq!(s.on_call_schedule_id.as_deref(), Some("sre"));
        assert_eq!(s.repository.as_deref(), Some("git@host:org/a"));
    }

    #[test]
    fn add_link_appends() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.add_link(
            "a",
            Link {
                label: "runbook".into(),
                url: "https://wiki/runbook".into(),
            },
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(c.get("a").unwrap().links.len(), 1);
    }

    #[test]
    fn add_compliance_dedupes() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.add_compliance("a", ComplianceScope::Soc2, "2025-05-02T00:00:00Z")
            .unwrap();
        c.add_compliance("a", ComplianceScope::Soc2, "2025-05-02T00:00:00Z")
            .unwrap();
        c.add_compliance("a", ComplianceScope::Iso27001, "2025-05-02T00:00:00Z")
            .unwrap();
        let s = c.get("a").unwrap();
        assert_eq!(
            s.compliance,
            vec![ComplianceScope::Soc2, ComplianceScope::Iso27001]
        );
    }

    #[test]
    fn add_slo_dedupes_by_slo_id() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.add_slo(
            "a",
            SloBinding {
                slo_id: "p99-latency".into(),
                label: "p99 < 500ms".into(),
            },
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        c.add_slo(
            "a",
            SloBinding {
                slo_id: "p99-latency".into(),
                label: "different label".into(),
            },
            "2025-05-02T00:00:00Z",
        )
        .unwrap();
        assert_eq!(c.get("a").unwrap().slos.len(), 1);
    }

    #[test]
    fn add_tag_dedupes() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.add_tag("a", "revenue", "2025-05-02T00:00:00Z").unwrap();
        c.add_tag("a", "revenue", "2025-05-02T00:00:00Z").unwrap();
        c.add_tag("a", "core", "2025-05-02T00:00:00Z").unwrap();
        assert_eq!(c.get("a").unwrap().tags, vec!["revenue", "core"]);
    }

    #[test]
    fn for_team_filters() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        let mut other = entry("b");
        other.owner_team = "data".into();
        c.register(other).unwrap();
        assert_eq!(c.for_team("platform").len(), 1);
        assert_eq!(c.for_team("data").len(), 1);
        assert_eq!(c.for_team("nope").len(), 0);
    }

    #[test]
    fn for_tenant_filters() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        let mut other = entry("b");
        other.tenant_id = "tenant-b".into();
        c.register(other).unwrap();
        assert_eq!(c.for_tenant("tenant-a").len(), 1);
        assert_eq!(c.for_tenant("tenant-b").len(), 1);
    }

    #[test]
    fn by_lifecycle_filters() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.register(entry("b")).unwrap();
        c.transition("a", LifecycleStage::Alpha, "2025-05-02T00:00:00Z")
            .unwrap();
        assert_eq!(c.by_lifecycle(LifecycleStage::Proposed).len(), 1);
        assert_eq!(c.by_lifecycle(LifecycleStage::Alpha).len(), 1);
        assert_eq!(c.by_lifecycle(LifecycleStage::Ga).len(), 0);
    }

    #[test]
    fn in_compliance_scope_filters() {
        let c = ServiceCatalog::new();
        c.register(entry("a")).unwrap();
        c.register(entry("b")).unwrap();
        c.add_compliance("a", ComplianceScope::Hipaa, "2025-05-02T00:00:00Z")
            .unwrap();
        assert_eq!(c.in_compliance_scope(ComplianceScope::Hipaa).len(), 1);
        assert_eq!(c.in_compliance_scope(ComplianceScope::Soc2).len(), 0);
    }

    #[test]
    fn missing_on_call_only_for_live_services() {
        let c = ServiceCatalog::new();
        // a → Beta with no on-call → flagged
        c.register(entry("a")).unwrap();
        c.transition("a", LifecycleStage::Alpha, "2025-05-02T00:00:00Z")
            .unwrap();
        c.transition("a", LifecycleStage::Beta, "2025-05-03T00:00:00Z")
            .unwrap();
        // b → Beta with on-call → not flagged
        c.register(entry("b")).unwrap();
        c.transition("b", LifecycleStage::Alpha, "2025-05-02T00:00:00Z")
            .unwrap();
        c.transition("b", LifecycleStage::Beta, "2025-05-03T00:00:00Z")
            .unwrap();
        c.set_on_call("b", "sre", "2025-05-03T00:00:00Z").unwrap();
        // c → Proposed (not live) with no on-call → not flagged
        c.register(entry("c")).unwrap();
        let missing = c.missing_on_call();
        let ids: Vec<_> = missing.iter().map(|s| s.service_id.clone()).collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[test]
    fn lifecycle_helpers() {
        assert!(LifecycleStage::Beta.is_live());
        assert!(LifecycleStage::Ga.is_live());
        assert!(LifecycleStage::Deprecated.is_live());
        assert!(!LifecycleStage::Proposed.is_live());
        assert!(!LifecycleStage::Alpha.is_live());
        assert!(!LifecycleStage::Retired.is_live());
        assert!(LifecycleStage::Retired.is_terminal());
        assert!(!LifecycleStage::Ga.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let c = ServiceCatalog::new();
        assert_eq!(c.count(), 0);
        c.register(entry("a")).unwrap();
        assert_eq!(c.count(), 1);
    }

    #[test]
    fn entry_serde() {
        let e = entry("a");
        let j = serde_json::to_string(&e).unwrap();
        let back: ServiceEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn lifecycle_serde() {
        for s in [
            LifecycleStage::Proposed,
            LifecycleStage::Alpha,
            LifecycleStage::Beta,
            LifecycleStage::Ga,
            LifecycleStage::Deprecated,
            LifecycleStage::Retired,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let back: LifecycleStage = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn compliance_serde() {
        for s in [
            ComplianceScope::Soc2,
            ComplianceScope::Iso27001,
            ComplianceScope::Hipaa,
            ComplianceScope::PciDss,
            ComplianceScope::Fedramp,
            ComplianceScope::Gdpr,
            ComplianceScope::Ccpa,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let back: ComplianceScope = serde_json::from_str(&j).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn link_and_slo_serde() {
        let l = Link {
            label: "x".into(),
            url: "y".into(),
        };
        let b = SloBinding {
            slo_id: "s".into(),
            label: "l".into(),
        };
        assert_eq!(
            l,
            serde_json::from_str::<Link>(&serde_json::to_string(&l).unwrap()).unwrap()
        );
        assert_eq!(
            b,
            serde_json::from_str::<SloBinding>(&serde_json::to_string(&b).unwrap()).unwrap()
        );
    }
}
