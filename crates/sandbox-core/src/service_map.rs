//! Service dependency map for blast-radius analysis.
//!
//! When an incident strikes service X, the on-call needs to know "what
//! else is downstream?" — within seconds, not after pulling out
//! architecture diagrams. This module is the deterministic dependency
//! graph: nodes are services, edges are typed dependencies (sync RPC,
//! async queue, data store, model dependency).
//!
//! The graph supports:
//!
//! - **Topological queries** — `descendants(svc)` returns transitive
//!   downstream services (i.e., what fails if `svc` fails).
//! - **Ancestors** — what services depend on `svc` (the upstream chain).
//! - **Cycle detection** — flag misconfigured graphs at registration.
//! - **Criticality propagation** — the criticality of a node is the max
//!   over its descendants.
//!
//! ## Why not Graphviz / external tool?
//!
//! Operators want this *in* the protocol so seal'd incident events can
//! reference a deterministic graph snapshot. External tools drift.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

// =============================================================================
// ServiceId
// =============================================================================

/// Stable service identifier (e.g., `"sandbox-finance"`, `"hsm"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServiceId(pub String);

impl ServiceId {
    /// New id.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// =============================================================================
// DependencyKind
// =============================================================================

/// Type of dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// Synchronous RPC.
    SyncRpc,
    /// Asynchronous queue / topic.
    AsyncQueue,
    /// Database / storage backend.
    DataStore,
    /// Model serving (dependent on a model service).
    ModelServing,
    /// Auth / identity provider.
    Auth,
    /// External / vendor.
    External,
}

// =============================================================================
// Criticality
// =============================================================================

/// Service criticality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    /// Tier-1 — outage = customer impact.
    Tier1,
    /// Tier-2 — degraded but not down.
    Tier2,
    /// Tier-3 — internal only.
    Tier3,
    /// Tier-4 — non-essential.
    Tier4,
}

impl Default for Criticality {
    fn default() -> Self {
        Criticality::Tier3
    }
}

// =============================================================================
// Service node
// =============================================================================

/// Node attributes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    /// Stable id.
    pub id: ServiceId,
    /// Display name.
    pub name: String,
    /// Owning team.
    pub owner: String,
    /// Criticality (declared — call `effective_criticality` for propagated).
    pub criticality: Criticality,
    /// Optional runbook URL.
    pub runbook_url: Option<String>,
}

// =============================================================================
// Dependency edge
// =============================================================================

/// Directed edge: `from` depends on `to` (calls / reads / writes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Dependency {
    /// Source.
    pub from: ServiceId,
    /// Target.
    pub to: ServiceId,
    /// Edge kind.
    pub kind: DependencyKind,
}

// =============================================================================
// ServiceMap
// =============================================================================

#[derive(Default)]
struct State {
    services: HashMap<ServiceId, Service>,
    /// `from` → set of `to`.
    edges_out: HashMap<ServiceId, HashSet<Dependency>>,
    /// `to` → set of `from`.
    edges_in: HashMap<ServiceId, HashSet<Dependency>>,
}

/// Service dependency graph.
pub struct ServiceMap {
    state: RwLock<State>,
}

impl Default for ServiceMap {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for ServiceMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceMap")
            .field("services", &self.service_count())
            .field("edges", &self.edge_count())
            .finish()
    }
}

impl ServiceMap {
    /// New empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service node.
    pub fn add_service(&self, s: Service) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("service map poisoned".into()))?;
        if g.services.contains_key(&s.id) {
            return Err(SandboxError::Other(format!(
                "service {} already registered",
                s.id.as_str()
            )));
        }
        g.services.insert(s.id.clone(), s);
        Ok(())
    }

    /// Add an edge.
    pub fn add_dependency(&self, dep: Dependency) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("service map poisoned".into()))?;
        if !g.services.contains_key(&dep.from) {
            return Err(SandboxError::Other(format!(
                "from-service {} not registered",
                dep.from.as_str()
            )));
        }
        if !g.services.contains_key(&dep.to) {
            return Err(SandboxError::Other(format!(
                "to-service {} not registered",
                dep.to.as_str()
            )));
        }
        if dep.from == dep.to {
            return Err(SandboxError::Other("self-dependency disallowed".into()));
        }
        // Cycle pre-check: would adding this create a cycle?
        let creates_cycle = path_exists(&g.edges_out, &dep.to, &dep.from);
        if creates_cycle {
            return Err(SandboxError::Other(format!(
                "dependency {}->{} would create a cycle",
                dep.from.as_str(),
                dep.to.as_str()
            )));
        }
        g.edges_out.entry(dep.from.clone()).or_default().insert(dep.clone());
        g.edges_in.entry(dep.to.clone()).or_default().insert(dep);
        Ok(())
    }

    /// Number of services.
    pub fn service_count(&self) -> usize {
        self.state.read().map(|g| g.services.len()).unwrap_or(0)
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.state
            .read()
            .map(|g| g.edges_out.values().map(|v| v.len()).sum())
            .unwrap_or(0)
    }

    /// Look up a service.
    pub fn service(&self, id: &ServiceId) -> Option<Service> {
        self.state.read().ok()?.services.get(id).cloned()
    }

    /// All services.
    pub fn services(&self) -> Vec<Service> {
        self.state
            .read()
            .map(|g| g.services.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Direct dependencies of a service.
    pub fn direct_dependencies(&self, id: &ServiceId) -> Vec<Dependency> {
        self.state
            .read()
            .map(|g| {
                g.edges_out
                    .get(id)
                    .cloned()
                    .map(|s| s.into_iter().collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Direct dependents (who depends on `id`).
    pub fn direct_dependents(&self, id: &ServiceId) -> Vec<Dependency> {
        self.state
            .read()
            .map(|g| {
                g.edges_in
                    .get(id)
                    .cloned()
                    .map(|s| s.into_iter().collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Transitive descendants — services `id` depends on (directly or
    /// indirectly).
    pub fn descendants(&self, id: &ServiceId) -> HashSet<ServiceId> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return HashSet::new(),
        };
        bfs(&g.edges_out, id, |d| d.to.clone())
    }

    /// Transitive ancestors — services that depend on `id`.
    pub fn ancestors(&self, id: &ServiceId) -> HashSet<ServiceId> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return HashSet::new(),
        };
        bfs(&g.edges_in, id, |d| d.from.clone())
    }

    /// Effective criticality propagated from ancestors. The result is the
    /// **highest** criticality (lowest tier number) of any ancestor — i.e.,
    /// if a service is a dependency of any tier-1, it's effectively tier-1.
    pub fn effective_criticality(&self, id: &ServiceId) -> Option<Criticality> {
        let g = self.state.read().ok()?;
        let own = g.services.get(id)?.criticality;
        let ancestors = bfs(&g.edges_in, id, |d| d.from.clone());
        let mut best = own;
        for a in &ancestors {
            if let Some(s) = g.services.get(a) {
                if s.criticality < best {
                    best = s.criticality;
                }
            }
        }
        Some(best)
    }

    /// Topological sort (returns Err if cycle detected — shouldn't happen
    /// since `add_dependency` rejects cycles, but useful as a sanity check).
    pub fn topo_sort(&self) -> SandboxResult<Vec<ServiceId>> {
        let g = self
            .state
            .read()
            .map_err(|_| SandboxError::Other("service map poisoned".into()))?;
        let mut indegree: HashMap<ServiceId, usize> = HashMap::new();
        for s in g.services.keys() {
            indegree.insert(s.clone(), 0);
        }
        for deps in g.edges_in.values() {
            for d in deps {
                *indegree.entry(d.to.clone()).or_insert(0) += 1;
            }
        }
        let mut queue: VecDeque<ServiceId> = indegree
            .iter()
            .filter(|(_, &d)| d == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut out = Vec::new();
        while let Some(n) = queue.pop_front() {
            out.push(n.clone());
            if let Some(deps) = g.edges_out.get(&n) {
                for d in deps {
                    let e = indegree.get_mut(&d.to).unwrap();
                    *e -= 1;
                    if *e == 0 {
                        queue.push_back(d.to.clone());
                    }
                }
            }
        }
        if out.len() != g.services.len() {
            return Err(SandboxError::Other("cycle detected in topo sort".into()));
        }
        Ok(out)
    }
}

fn path_exists(
    edges: &HashMap<ServiceId, HashSet<Dependency>>,
    src: &ServiceId,
    dst: &ServiceId,
) -> bool {
    let mut visited: HashSet<ServiceId> = HashSet::new();
    let mut stack = vec![src.clone()];
    while let Some(n) = stack.pop() {
        if &n == dst {
            return true;
        }
        if !visited.insert(n.clone()) {
            continue;
        }
        if let Some(out) = edges.get(&n) {
            for d in out {
                stack.push(d.to.clone());
            }
        }
    }
    false
}

fn bfs<F: Fn(&Dependency) -> ServiceId>(
    edges: &HashMap<ServiceId, HashSet<Dependency>>,
    start: &ServiceId,
    next: F,
) -> HashSet<ServiceId> {
    let mut visited: HashSet<ServiceId> = HashSet::new();
    let mut queue: VecDeque<ServiceId> = VecDeque::new();
    if let Some(out) = edges.get(start) {
        for d in out {
            queue.push_back(next(d));
        }
    }
    while let Some(n) = queue.pop_front() {
        if !visited.insert(n.clone()) {
            continue;
        }
        if let Some(out) = edges.get(&n) {
            for d in out {
                queue.push_back(next(d));
            }
        }
    }
    visited
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: &str, t: Criticality) -> Service {
        Service {
            id: ServiceId::new(id),
            name: id.into(),
            owner: "team".into(),
            criticality: t,
            runbook_url: None,
        }
    }

    fn dep(from: &str, to: &str) -> Dependency {
        Dependency {
            from: ServiceId::new(from),
            to: ServiceId::new(to),
            kind: DependencyKind::SyncRpc,
        }
    }

    #[test]
    fn add_service_increments() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        assert_eq!(m.service_count(), 1);
    }

    #[test]
    fn duplicate_service_errors() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        assert!(m.add_service(svc("a", Criticality::Tier2)).is_err());
    }

    #[test]
    fn add_edge_after_services() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        assert_eq!(m.edge_count(), 1);
    }

    #[test]
    fn add_edge_to_unknown_errors() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        assert!(m.add_dependency(dep("a", "ghost")).is_err());
        assert!(m.add_dependency(dep("ghost", "a")).is_err());
    }

    #[test]
    fn self_dependency_rejected() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        assert!(m.add_dependency(dep("a", "a")).is_err());
    }

    #[test]
    fn cycle_rejected() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_service(svc("c", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        m.add_dependency(dep("b", "c")).unwrap();
        // c -> a would create a cycle.
        assert!(m.add_dependency(dep("c", "a")).is_err());
    }

    #[test]
    fn descendants_transitive() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_service(svc("c", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        m.add_dependency(dep("b", "c")).unwrap();
        let d = m.descendants(&ServiceId::new("a"));
        assert!(d.contains(&ServiceId::new("b")));
        assert!(d.contains(&ServiceId::new("c")));
    }

    #[test]
    fn ancestors_transitive() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_service(svc("c", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        m.add_dependency(dep("b", "c")).unwrap();
        let anc = m.ancestors(&ServiceId::new("c"));
        assert!(anc.contains(&ServiceId::new("a")));
        assert!(anc.contains(&ServiceId::new("b")));
    }

    #[test]
    fn direct_dependencies_lookup() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        let d = m.direct_dependencies(&ServiceId::new("a"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn direct_dependents_lookup() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        let d = m.direct_dependents(&ServiceId::new("b"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn effective_criticality_propagates() {
        let m = ServiceMap::new();
        m.add_service(svc("api", Criticality::Tier1)).unwrap();
        m.add_service(svc("hsm", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("api", "hsm")).unwrap();
        // Even though hsm is declared tier-3, it's effectively tier-1
        // because tier-1 api depends on it.
        assert_eq!(
            m.effective_criticality(&ServiceId::new("hsm")),
            Some(Criticality::Tier1)
        );
    }

    #[test]
    fn topo_sort_correct() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_service(svc("c", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        m.add_dependency(dep("b", "c")).unwrap();
        let order = m.topo_sort().unwrap();
        let pos: HashMap<ServiceId, usize> =
            order.iter().enumerate().map(|(i, s)| (s.clone(), i)).collect();
        assert!(pos[&ServiceId::new("a")] < pos[&ServiceId::new("b")]);
        assert!(pos[&ServiceId::new("b")] < pos[&ServiceId::new("c")]);
    }

    #[test]
    fn topo_sort_empty_returns_empty() {
        let m = ServiceMap::new();
        assert!(m.topo_sort().unwrap().is_empty());
    }

    #[test]
    fn services_returns_all() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        assert_eq!(m.services().len(), 2);
    }

    #[test]
    fn lookup_returns_clone() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        let s = m.service(&ServiceId::new("a")).unwrap();
        assert_eq!(s.id, ServiceId::new("a"));
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let m = ServiceMap::new();
        assert!(m.service(&ServiceId::new("ghost")).is_none());
    }

    #[test]
    fn descendants_of_unknown_empty() {
        let m = ServiceMap::new();
        let d = m.descendants(&ServiceId::new("ghost"));
        assert!(d.is_empty());
    }

    #[test]
    fn ancestors_of_unknown_empty() {
        let m = ServiceMap::new();
        let a = m.ancestors(&ServiceId::new("ghost"));
        assert!(a.is_empty());
    }

    #[test]
    fn diamond_descendants() {
        let m = ServiceMap::new();
        m.add_service(svc("a", Criticality::Tier1)).unwrap();
        m.add_service(svc("b", Criticality::Tier2)).unwrap();
        m.add_service(svc("c", Criticality::Tier2)).unwrap();
        m.add_service(svc("d", Criticality::Tier3)).unwrap();
        m.add_dependency(dep("a", "b")).unwrap();
        m.add_dependency(dep("a", "c")).unwrap();
        m.add_dependency(dep("b", "d")).unwrap();
        m.add_dependency(dep("c", "d")).unwrap();
        let d = m.descendants(&ServiceId::new("a"));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn dependency_kind_serde() {
        for k in [
            DependencyKind::SyncRpc,
            DependencyKind::AsyncQueue,
            DependencyKind::DataStore,
            DependencyKind::ModelServing,
            DependencyKind::Auth,
            DependencyKind::External,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: DependencyKind = serde_json::from_str(&j).unwrap();
            assert_eq!(p, k);
        }
    }

    #[test]
    fn criticality_ordering_correct() {
        assert!(Criticality::Tier1 < Criticality::Tier2);
        assert!(Criticality::Tier2 < Criticality::Tier3);
    }

    #[test]
    fn service_serde() {
        let s = svc("a", Criticality::Tier1);
        let j = serde_json::to_string(&s).unwrap();
        let p: Service = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn dependency_serde() {
        let d = dep("a", "b");
        let j = serde_json::to_string(&d).unwrap();
        let p: Dependency = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn service_id_serde_transparent() {
        let id = ServiceId::new("x");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"x\"");
    }

    #[test]
    fn many_services_topo_sort() {
        let m = ServiceMap::new();
        for i in 0..10 {
            m.add_service(svc(&format!("s{i}"), Criticality::Tier3)).unwrap();
        }
        for i in 0..9 {
            m.add_dependency(dep(&format!("s{i}"), &format!("s{}", i + 1)))
                .unwrap();
        }
        let order = m.topo_sort().unwrap();
        assert_eq!(order.len(), 10);
    }
}
