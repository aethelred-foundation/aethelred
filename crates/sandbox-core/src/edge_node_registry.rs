//! Per-region edge / POP node registry.
//!
//! Records every edge node serving traffic. Each node has region, capacity,
//! current load, health, and supported sectors. Used by load balancers to
//! pick targets and by ops to drain nodes for maintenance.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;

// =============================================================================
// NodeStatus
// =============================================================================

/// Per-node status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Healthy and serving.
    Active,
    /// Draining: stop sending new traffic.
    Draining,
    /// Maintenance: out of rotation.
    Maintenance,
    /// Failed health check.
    Unhealthy,
    /// Decommissioned.
    Decommissioned,
}

// =============================================================================
// EdgeNode
// =============================================================================

/// One edge node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EdgeNode {
    /// Stable id.
    pub node_id: String,
    /// Region.
    pub region: String,
    /// Datacenter / pop label.
    pub pop: String,
    /// Capacity (e.g. max concurrent sessions).
    pub capacity: u32,
    /// Current load.
    pub current_load: u32,
    /// Status.
    pub status: NodeStatus,
    /// Public hostname.
    pub hostname: String,
    /// Internal IP / private endpoint.
    pub internal_endpoint: String,
    /// Supported sectors.
    pub supported_sectors: Vec<String>,
    /// RFC 3339 last health check.
    pub last_health_check_at: Option<String>,
    /// Software version running.
    pub version: String,
    /// RFC 3339 registered.
    pub registered_at: String,
}

impl EdgeNode {
    /// Utilization in `[0.0, 1.0]`.
    pub fn utilization(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        (self.current_load as f64 / self.capacity as f64).min(1.0)
    }
    /// `true` if node accepts new requests.
    pub fn accepts_traffic(&self) -> bool {
        self.status == NodeStatus::Active && self.current_load < self.capacity
    }
}

// =============================================================================
// EdgeNodeRegistry
// =============================================================================

#[derive(Default)]
struct State {
    nodes: HashMap<String, EdgeNode>,
}

/// Registry.
pub struct EdgeNodeRegistry {
    state: RwLock<State>,
}

impl Default for EdgeNodeRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for EdgeNodeRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeNodeRegistry")
            .field("nodes", &self.len())
            .finish()
    }
}

impl EdgeNodeRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a node.
    pub fn register(&self, node: EdgeNode) -> SandboxResult<()> {
        if node.capacity == 0 {
            return Err(SandboxError::Other("capacity must be > 0".into()));
        }
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("edge registry poisoned".into()))?;
        if g.nodes.contains_key(&node.node_id) {
            return Err(SandboxError::Other(format!(
                "node {} already registered",
                node.node_id
            )));
        }
        g.nodes.insert(node.node_id.clone(), node);
        Ok(())
    }

    /// Update load.
    pub fn report_load(&self, node_id: &str, load: u32) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("edge registry poisoned".into()))?;
        let n = g
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| SandboxError::Other(format!("node {} not found", node_id)))?;
        n.current_load = load;
        Ok(())
    }

    /// Update status.
    pub fn set_status(&self, node_id: &str, status: NodeStatus) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("edge registry poisoned".into()))?;
        let n = g
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| SandboxError::Other(format!("node {} not found", node_id)))?;
        n.status = status;
        Ok(())
    }

    /// Record a health check at now.
    pub fn record_health_check(&self, node_id: &str, healthy: bool) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("edge registry poisoned".into()))?;
        let n = g
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| SandboxError::Other(format!("node {} not found", node_id)))?;
        n.last_health_check_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        if !healthy && n.status == NodeStatus::Active {
            n.status = NodeStatus::Unhealthy;
        }
        if healthy && n.status == NodeStatus::Unhealthy {
            n.status = NodeStatus::Active;
        }
        Ok(())
    }

    /// Lookup.
    pub fn get(&self, id: &str) -> Option<EdgeNode> {
        self.state.read().ok()?.nodes.get(id).cloned()
    }

    /// All.
    pub fn all(&self) -> Vec<EdgeNode> {
        self.state
            .read()
            .map(|g| g.nodes.values().cloned().collect())
            .unwrap_or_default()
    }

    /// By region.
    pub fn for_region(&self, region: &str) -> Vec<EdgeNode> {
        self.all().into_iter().filter(|n| n.region == region).collect()
    }

    /// Active nodes accepting traffic in a region.
    pub fn available_in(&self, region: &str) -> Vec<EdgeNode> {
        self.for_region(region)
            .into_iter()
            .filter(|n| n.accepts_traffic())
            .collect()
    }

    /// All nodes supporting a sector.
    pub fn supporting_sector(&self, sector: &str) -> Vec<EdgeNode> {
        self.all()
            .into_iter()
            .filter(|n| n.supported_sectors.iter().any(|s| s == sector))
            .collect()
    }

    /// Pick the least-loaded available node in a region (returns first if tied).
    pub fn pick_least_loaded(&self, region: &str) -> Option<EdgeNode> {
        let mut available: Vec<EdgeNode> = self.available_in(region);
        if available.is_empty() {
            return None;
        }
        available.sort_by(|a, b| {
            a.utilization()
                .partial_cmp(&b.utilization())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Some(available.into_iter().next().unwrap())
    }

    /// Aggregate utilization across a region (mean over active nodes).
    pub fn region_utilization(&self, region: &str) -> f64 {
        let active: Vec<EdgeNode> = self
            .for_region(region)
            .into_iter()
            .filter(|n| n.status == NodeStatus::Active)
            .collect();
        if active.is_empty() {
            return 0.0;
        }
        let total: f64 = active.iter().map(|n| n.utilization()).sum();
        total / active.len() as f64
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.nodes.len()).unwrap_or(0)
    }

    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, region: &str, capacity: u32) -> EdgeNode {
        EdgeNode {
            node_id: id.into(),
            region: region.into(),
            pop: format!("{region}-pop-1"),
            capacity,
            current_load: 0,
            status: NodeStatus::Active,
            hostname: format!("{id}.example.test"),
            internal_endpoint: format!("10.0.0.{id}"),
            supported_sectors: vec!["finance".into()],
            last_health_check_at: None,
            version: "0.2.19".into(),
            registered_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    #[test]
    fn register_succeeds() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn duplicate_register_errors() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        assert!(r.register(node("n1", "eu-west-1", 100)).is_err());
    }

    #[test]
    fn zero_capacity_errors() {
        let r = EdgeNodeRegistry::new();
        assert!(r.register(node("n1", "eu-west-1", 0)).is_err());
    }

    #[test]
    fn report_load_updates() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.report_load("n1", 75).unwrap();
        let n = r.get("n1").unwrap();
        assert_eq!(n.current_load, 75);
        assert!((n.utilization() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn utilization_clamped() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.report_load("n1", 200).unwrap();
        assert_eq!(r.get("n1").unwrap().utilization(), 1.0);
    }

    #[test]
    fn accepts_traffic_when_active_and_under_cap() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        assert!(r.get("n1").unwrap().accepts_traffic());
    }

    #[test]
    fn at_capacity_does_not_accept() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.report_load("n1", 100).unwrap();
        assert!(!r.get("n1").unwrap().accepts_traffic());
    }

    #[test]
    fn draining_does_not_accept() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.set_status("n1", NodeStatus::Draining).unwrap();
        assert!(!r.get("n1").unwrap().accepts_traffic());
    }

    #[test]
    fn health_check_unhealthy_changes_status() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.record_health_check("n1", false).unwrap();
        assert_eq!(r.get("n1").unwrap().status, NodeStatus::Unhealthy);
    }

    #[test]
    fn health_check_healthy_recovers_status() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.record_health_check("n1", false).unwrap();
        r.record_health_check("n1", true).unwrap();
        assert_eq!(r.get("n1").unwrap().status, NodeStatus::Active);
    }

    #[test]
    fn for_region_filters() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.register(node("n2", "us-east-1", 100)).unwrap();
        assert_eq!(r.for_region("eu-west-1").len(), 1);
        assert_eq!(r.for_region("us-east-1").len(), 1);
    }

    #[test]
    fn available_in_excludes_unhealthy() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.register(node("n2", "eu-west-1", 100)).unwrap();
        r.set_status("n2", NodeStatus::Maintenance).unwrap();
        assert_eq!(r.available_in("eu-west-1").len(), 1);
    }

    #[test]
    fn pick_least_loaded_returns_lowest() {
        let r = EdgeNodeRegistry::new();
        r.register(node("a", "eu-west-1", 100)).unwrap();
        r.register(node("b", "eu-west-1", 100)).unwrap();
        r.register(node("c", "eu-west-1", 100)).unwrap();
        r.report_load("a", 80).unwrap();
        r.report_load("b", 20).unwrap();
        r.report_load("c", 50).unwrap();
        let picked = r.pick_least_loaded("eu-west-1").unwrap();
        assert_eq!(picked.node_id, "b");
    }

    #[test]
    fn pick_least_loaded_no_available_returns_none() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.set_status("n1", NodeStatus::Maintenance).unwrap();
        assert!(r.pick_least_loaded("eu-west-1").is_none());
    }

    #[test]
    fn supporting_sector_filters() {
        let r = EdgeNodeRegistry::new();
        let mut n = node("n1", "eu-west-1", 100);
        n.supported_sectors = vec!["finance".into(), "healthcare".into()];
        r.register(n).unwrap();
        assert_eq!(r.supporting_sector("finance").len(), 1);
        assert_eq!(r.supporting_sector("healthcare").len(), 1);
        assert_eq!(r.supporting_sector("defense").len(), 0);
    }

    #[test]
    fn region_utilization_mean() {
        let r = EdgeNodeRegistry::new();
        r.register(node("a", "eu-west-1", 100)).unwrap();
        r.register(node("b", "eu-west-1", 100)).unwrap();
        r.report_load("a", 80).unwrap();
        r.report_load("b", 20).unwrap();
        assert!((r.region_utilization("eu-west-1") - 0.5).abs() < 1e-9);
    }

    #[test]
    fn region_utilization_no_active_zero() {
        let r = EdgeNodeRegistry::new();
        assert_eq!(r.region_utilization("eu-west-1"), 0.0);
    }

    #[test]
    fn node_serde() {
        let n = node("n1", "eu-west-1", 100);
        let j = serde_json::to_string(&n).unwrap();
        let p: EdgeNode = serde_json::from_str(&j).unwrap();
        assert_eq!(p, n);
    }

    #[test]
    fn status_serde() {
        for s in [
            NodeStatus::Active,
            NodeStatus::Draining,
            NodeStatus::Maintenance,
            NodeStatus::Unhealthy,
            NodeStatus::Decommissioned,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: NodeStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn report_load_unknown_errors() {
        let r = EdgeNodeRegistry::new();
        assert!(r.report_load("ghost", 10).is_err());
    }

    #[test]
    fn count_tracks() {
        let r = EdgeNodeRegistry::new();
        assert!(r.is_empty());
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn last_health_check_recorded() {
        let r = EdgeNodeRegistry::new();
        r.register(node("n1", "eu-west-1", 100)).unwrap();
        r.record_health_check("n1", true).unwrap();
        assert!(r.get("n1").unwrap().last_health_check_at.is_some());
    }

    #[test]
    fn all_returns_all() {
        let r = EdgeNodeRegistry::new();
        for i in 0..5 {
            r.register(node(&format!("n{i}"), "eu-west-1", 100)).unwrap();
        }
        assert_eq!(r.all().len(), 5);
    }
}
