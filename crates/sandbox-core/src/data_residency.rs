//! Data residency — jurisdiction → region geo-fencing.
//!
//! GDPR (EU), PIPL (China), DIFC (UAE), HIPAA (US-East controlled), FedRAMP
//! (gov regions only) all require that data for a given jurisdiction is
//! stored *only* in approved regions. This module enforces that at the
//! routing layer.
//!
//! ## Model
//!
//! - A [`Jurisdiction`] tags data (e.g., `"EU"`, `"CN"`, `"AE"`, `"US"`).
//! - A [`Region`] identifies a physical-storage cell (e.g., `"eu-west-1"`,
//!   `"me-central-1"`).
//! - A [`ResidencyPolicy`] declares which regions are allowed for one
//!   jurisdiction. Routing failures produce [`ResidencyDenial`] events for
//!   the audit trail.
//!
//! ## Example
//!
//! ```ignore
//! let mut reg = ResidencyRegistry::new();
//! reg.register(ResidencyPolicy::new(Jurisdiction::new("EU"))
//!     .allow(Region::new("eu-west-1"))
//!     .allow(Region::new("eu-central-1")));
//! reg.register(ResidencyPolicy::new(Jurisdiction::new("CN"))
//!     .allow(Region::new("cn-beijing-1")));
//!
//! match reg.route(&Jurisdiction::new("EU"), &Region::new("us-east-1")) {
//!     RoutingDecision::Allow => /* normal */,
//!     RoutingDecision::Deny(d) => /* audit, fall-back, etc. */,
//! }
//! ```

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// Jurisdiction + Region
// =============================================================================

/// Jurisdiction tag (e.g. `"EU"`, `"CN"`, `"AE"`, `"US"`, `"US-FED"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Jurisdiction(pub String);

impl Jurisdiction {
    /// New tag.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Storage region identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Region(pub String);

impl Region {
    /// New region.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// As `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// ResidencyPolicy
// =============================================================================

/// One jurisdiction's residency policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidencyPolicy {
    /// Jurisdiction this policy applies to.
    pub jurisdiction: Jurisdiction,
    /// Set of allowed regions.
    pub allowed_regions: Vec<Region>,
    /// Optional human-readable note ("GDPR Art. 44–50").
    pub note: Option<String>,
}

impl ResidencyPolicy {
    /// New policy with no allowed regions.
    pub fn new(j: Jurisdiction) -> Self {
        Self {
            jurisdiction: j,
            allowed_regions: Vec::new(),
            note: None,
        }
    }

    /// Builder: allow a region.
    pub fn allow(mut self, r: Region) -> Self {
        if !self.allowed_regions.contains(&r) {
            self.allowed_regions.push(r);
        }
        self
    }

    /// Builder: many regions.
    pub fn allow_all<I: IntoIterator<Item = Region>>(mut self, rs: I) -> Self {
        for r in rs {
            if !self.allowed_regions.contains(&r) {
                self.allowed_regions.push(r);
            }
        }
        self
    }

    /// Builder: note.
    pub fn with_note(mut self, n: impl Into<String>) -> Self {
        self.note = Some(n.into());
        self
    }

    /// `true` if `r` is allowed.
    pub fn allows(&self, r: &Region) -> bool {
        self.allowed_regions.contains(r)
    }
}

// =============================================================================
// RoutingDecision + ResidencyDenial
// =============================================================================

/// Outcome of a routing check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RoutingDecision {
    /// Allowed.
    Allow,
    /// Denied — see record.
    Deny(ResidencyDenial),
}

impl RoutingDecision {
    /// `true` if allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, RoutingDecision::Allow)
    }
}

/// Record of a residency-policy violation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResidencyDenial {
    /// RFC 3339 wall-clock.
    pub at: String,
    /// Jurisdiction the data was tagged with.
    pub jurisdiction: Jurisdiction,
    /// Requested region.
    pub requested_region: Region,
    /// Allowed-region set the requested region failed to match.
    pub allowed_regions: Vec<Region>,
    /// Optional reason ("no policy registered" vs "region not in allow list").
    pub reason: String,
}

// =============================================================================
// ResidencyRegistry
// =============================================================================

#[derive(Default)]
struct RegistryState {
    policies: HashMap<Jurisdiction, ResidencyPolicy>,
    denials: Vec<ResidencyDenial>,
    /// `true` if the registry should fail-closed (deny if no policy).
    fail_closed: bool,
}

/// Registry of residency policies plus a denial log.
pub struct ResidencyRegistry {
    state: RwLock<RegistryState>,
}

impl std::fmt::Debug for ResidencyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (p, d, fc) = self
            .state
            .read()
            .map(|g| (g.policies.len(), g.denials.len(), g.fail_closed))
            .unwrap_or((0, 0, false));
        f.debug_struct("ResidencyRegistry")
            .field("policies", &p)
            .field("denials", &d)
            .field("fail_closed", &fc)
            .finish()
    }
}

impl Default for ResidencyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ResidencyRegistry {
    /// New empty registry, **fail-closed by default** (no policy → deny).
    pub fn new() -> Self {
        Self {
            state: RwLock::new(RegistryState {
                policies: HashMap::new(),
                denials: Vec::new(),
                fail_closed: true,
            }),
        }
    }

    /// Configure failure mode. `true` (default) = deny when no policy
    /// matches. `false` = allow.
    pub fn set_fail_closed(&self, fc: bool) {
        if let Ok(mut g) = self.state.write() {
            g.fail_closed = fc;
        }
    }

    /// `true` if fail-closed mode.
    pub fn is_fail_closed(&self) -> bool {
        self.state.read().map(|g| g.fail_closed).unwrap_or(true)
    }

    /// Register a policy. Errors if it has an empty allow list (which would
    /// guarantee 100% denial — almost certainly a config bug).
    pub fn register(&self, p: ResidencyPolicy) -> SandboxResult<()> {
        if p.allowed_regions.is_empty() {
            return Err(SandboxError::Other(format!(
                "residency policy for {} has empty allow list",
                p.jurisdiction.as_str()
            )));
        }
        self.state
            .write()
            .map_err(|_| SandboxError::Other("residency registry poisoned".into()))?
            .policies
            .insert(p.jurisdiction.clone(), p);
        Ok(())
    }

    /// Number of policies registered.
    pub fn policy_count(&self) -> usize {
        self.state.read().map(|g| g.policies.len()).unwrap_or(0)
    }

    /// Look up a policy.
    pub fn policy(&self, j: &Jurisdiction) -> Option<ResidencyPolicy> {
        self.state.read().ok()?.policies.get(j).cloned()
    }

    /// Decide whether `region` is permitted for data tagged `j`.
    pub fn route(&self, j: &Jurisdiction, region: &Region) -> RoutingDecision {
        let mut g = match self.state.write() {
            Ok(g) => g,
            Err(_) => return self.deny(j, region, "registry lock poisoned", &[]),
        };
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        match g.policies.get(j) {
            Some(p) if p.allows(region) => RoutingDecision::Allow,
            Some(p) => {
                let d = ResidencyDenial {
                    at: now,
                    jurisdiction: j.clone(),
                    requested_region: region.clone(),
                    allowed_regions: p.allowed_regions.clone(),
                    reason: "region not in allow list".into(),
                };
                g.denials.push(d.clone());
                RoutingDecision::Deny(d)
            }
            None => {
                if g.fail_closed {
                    let d = ResidencyDenial {
                        at: now,
                        jurisdiction: j.clone(),
                        requested_region: region.clone(),
                        allowed_regions: Vec::new(),
                        reason: "no policy registered (fail-closed)".into(),
                    };
                    g.denials.push(d.clone());
                    RoutingDecision::Deny(d)
                } else {
                    RoutingDecision::Allow
                }
            }
        }
    }

    fn deny(
        &self,
        j: &Jurisdiction,
        region: &Region,
        reason: &str,
        allowed: &[Region],
    ) -> RoutingDecision {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        RoutingDecision::Deny(ResidencyDenial {
            at: now,
            jurisdiction: j.clone(),
            requested_region: region.clone(),
            allowed_regions: allowed.to_vec(),
            reason: reason.to_string(),
        })
    }

    /// All denials recorded so far.
    pub fn denials(&self) -> Vec<ResidencyDenial> {
        self.state.read().map(|g| g.denials.clone()).unwrap_or_default()
    }

    /// Number of denials recorded.
    pub fn denial_count(&self) -> usize {
        self.state.read().map(|g| g.denials.len()).unwrap_or(0)
    }

    /// Clear denial log (useful for tests).
    pub fn clear_denials(&self) {
        if let Ok(mut g) = self.state.write() {
            g.denials.clear();
        }
    }

    /// Set of all unique allowed regions across all policies.
    pub fn all_allowed_regions(&self) -> Vec<Region> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut set: HashSet<Region> = HashSet::new();
        for p in g.policies.values() {
            for r in &p.allowed_regions {
                set.insert(r.clone());
            }
        }
        let mut v: Vec<Region> = set.into_iter().collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eu_policy() -> ResidencyPolicy {
        ResidencyPolicy::new(Jurisdiction::new("EU"))
            .allow(Region::new("eu-west-1"))
            .allow(Region::new("eu-central-1"))
            .with_note("GDPR Art. 44–50")
    }

    fn cn_policy() -> ResidencyPolicy {
        ResidencyPolicy::new(Jurisdiction::new("CN"))
            .allow(Region::new("cn-beijing-1"))
            .with_note("PIPL")
    }

    #[test]
    fn jurisdiction_serde_transparent() {
        let j = Jurisdiction::new("EU");
        assert_eq!(serde_json::to_string(&j).unwrap(), "\"EU\"");
    }

    #[test]
    fn region_serde_transparent() {
        let r = Region::new("eu-west-1");
        assert_eq!(serde_json::to_string(&r).unwrap(), "\"eu-west-1\"");
    }

    #[test]
    fn policy_allows_listed_regions() {
        let p = eu_policy();
        assert!(p.allows(&Region::new("eu-west-1")));
        assert!(!p.allows(&Region::new("us-east-1")));
    }

    #[test]
    fn policy_dedupes_allow() {
        let p = ResidencyPolicy::new(Jurisdiction::new("EU"))
            .allow(Region::new("eu-west-1"))
            .allow(Region::new("eu-west-1"));
        assert_eq!(p.allowed_regions.len(), 1);
    }

    #[test]
    fn allow_all_adds_many() {
        let p = ResidencyPolicy::new(Jurisdiction::new("EU")).allow_all(vec![
            Region::new("eu-west-1"),
            Region::new("eu-central-1"),
        ]);
        assert_eq!(p.allowed_regions.len(), 2);
    }

    #[test]
    fn registry_register_and_count() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        r.register(cn_policy()).unwrap();
        assert_eq!(r.policy_count(), 2);
    }

    #[test]
    fn register_rejects_empty_allow_list() {
        let r = ResidencyRegistry::new();
        let p = ResidencyPolicy::new(Jurisdiction::new("EU"));
        assert!(r.register(p).is_err());
    }

    #[test]
    fn route_allows_in_region() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        let d = r.route(&Jurisdiction::new("EU"), &Region::new("eu-west-1"));
        assert!(d.is_allowed());
    }

    #[test]
    fn route_denies_out_of_region() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        let d = r.route(&Jurisdiction::new("EU"), &Region::new("us-east-1"));
        match d {
            RoutingDecision::Deny(rec) => {
                assert_eq!(rec.requested_region, Region::new("us-east-1"));
                assert!(rec.reason.contains("not in allow list"));
            }
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn route_records_denial() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        r.route(&Jurisdiction::new("EU"), &Region::new("us-east-1"));
        assert_eq!(r.denial_count(), 1);
    }

    #[test]
    fn fail_closed_denies_unknown_jurisdiction() {
        let r = ResidencyRegistry::new();
        let d = r.route(&Jurisdiction::new("XX"), &Region::new("eu-west-1"));
        assert!(!d.is_allowed());
    }

    #[test]
    fn fail_open_allows_unknown_jurisdiction() {
        let r = ResidencyRegistry::new();
        r.set_fail_closed(false);
        let d = r.route(&Jurisdiction::new("XX"), &Region::new("us-east-1"));
        assert!(d.is_allowed());
    }

    #[test]
    fn fail_closed_default() {
        let r = ResidencyRegistry::new();
        assert!(r.is_fail_closed());
    }

    #[test]
    fn policy_lookup_returns_clone() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        let p = r.policy(&Jurisdiction::new("EU")).unwrap();
        assert_eq!(p.allowed_regions.len(), 2);
    }

    #[test]
    fn policy_lookup_unknown_returns_none() {
        let r = ResidencyRegistry::new();
        assert!(r.policy(&Jurisdiction::new("Z")).is_none());
    }

    #[test]
    fn all_allowed_regions_unions_across_policies() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        r.register(cn_policy()).unwrap();
        let mut all: Vec<String> = r.all_allowed_regions().into_iter().map(|r| r.0).collect();
        all.sort();
        assert_eq!(all, vec!["cn-beijing-1", "eu-central-1", "eu-west-1"]);
    }

    #[test]
    fn clear_denials_empties_log() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        r.route(&Jurisdiction::new("EU"), &Region::new("us-east-1"));
        r.clear_denials();
        assert_eq!(r.denial_count(), 0);
    }

    #[test]
    fn policy_with_note_preserves_text() {
        let p = eu_policy();
        assert_eq!(p.note.as_deref(), Some("GDPR Art. 44–50"));
    }

    #[test]
    fn deny_decision_is_not_allowed() {
        let d = RoutingDecision::Deny(ResidencyDenial {
            at: "x".into(),
            jurisdiction: Jurisdiction::new("EU"),
            requested_region: Region::new("us-east-1"),
            allowed_regions: vec![],
            reason: "x".into(),
        });
        assert!(!d.is_allowed());
    }

    #[test]
    fn routing_decision_serde_round_trip() {
        let d_allow = RoutingDecision::Allow;
        let j_allow = serde_json::to_string(&d_allow).unwrap();
        let p_allow: RoutingDecision = serde_json::from_str(&j_allow).unwrap();
        assert_eq!(p_allow, d_allow);

        let d_deny = RoutingDecision::Deny(ResidencyDenial {
            at: "2026-01-01T00:00:00Z".into(),
            jurisdiction: Jurisdiction::new("EU"),
            requested_region: Region::new("us-east-1"),
            allowed_regions: vec![Region::new("eu-west-1")],
            reason: "x".into(),
        });
        let j_deny = serde_json::to_string(&d_deny).unwrap();
        let p_deny: RoutingDecision = serde_json::from_str(&j_deny).unwrap();
        assert_eq!(p_deny, d_deny);
    }

    #[test]
    fn residency_policy_serde_round_trip() {
        let p = eu_policy();
        let j = serde_json::to_string(&p).unwrap();
        let q: ResidencyPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn many_routes_recorded() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        for _ in 0..20 {
            r.route(&Jurisdiction::new("EU"), &Region::new("us-east-1"));
        }
        assert_eq!(r.denial_count(), 20);
    }

    #[test]
    fn route_for_two_jurisdictions_does_not_cross() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        r.register(cn_policy()).unwrap();
        // EU jurisdiction → cn region must deny.
        let d = r.route(&Jurisdiction::new("EU"), &Region::new("cn-beijing-1"));
        assert!(!d.is_allowed());
        // CN jurisdiction → cn region allowed.
        let d = r.route(&Jurisdiction::new("CN"), &Region::new("cn-beijing-1"));
        assert!(d.is_allowed());
    }

    #[test]
    fn policy_overwrite_replaces_old() {
        let r = ResidencyRegistry::new();
        r.register(eu_policy()).unwrap();
        // New EU policy: only eu-west-1.
        let p2 = ResidencyPolicy::new(Jurisdiction::new("EU"))
            .allow(Region::new("eu-west-1"));
        r.register(p2).unwrap();
        let p = r.policy(&Jurisdiction::new("EU")).unwrap();
        assert_eq!(p.allowed_regions.len(), 1);
    }
}
