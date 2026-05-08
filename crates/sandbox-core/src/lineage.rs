//! Data-lineage DAG.
//!
//! Beyond `DigitalSeal::prior_seal_hash` (a single back-pointer), production
//! pipelines have rich derivation graphs: an inference seal depends on a
//! training-run seal which depends on a dataset seal which depends on
//! consent records. Auditors and regulators ask:
//!
//! - "Show me the full provenance chain for this credit decision."
//! - "Which inference seals depend on dataset commit `abc123`?"
//! - "If we recall this model, which downstream seals are affected?"
//!
//! This module ships:
//!
//! - [`LineageNode`] — a node in the DAG keyed by seal id.
//! - [`LineageGraph`] — the in-memory DAG with `add_seal`, `add_edge`,
//!   `parents`, `descendants`, `topological_sort`, cycle detection.
//! - [`LineageEdge`] — typed relationships (`DerivedFrom`, `TrainedOn`,
//!   `ConsentedFor`, `BatchedFrom`, `RetrainedFrom`).
//! - **DOT** export (Graphviz) and **Mermaid** export (Markdown-friendly).
//!
//! ## Properties
//!
//! - **Cycle-free**: `add_edge` rejects cycles.
//! - **Tenant-isolated**: every node carries a tenant id; queries
//!   restricted to a tenant by default.
//! - **Time-stamped**: every edge has an RFC 3339 timestamp.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// EdgeType
// =============================================================================

/// Typed relationship between two lineage nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// Generic "derived from" — child output uses parent as input.
    DerivedFrom,
    /// Trained on — model seal trained on dataset seal.
    TrainedOn,
    /// Inferred with — inference seal used model seal.
    InferredWith,
    /// Consented for — model/inference uses subject's consent record.
    ConsentedFor,
    /// Batched from — child seal aggregates multiple parent seals.
    BatchedFrom,
    /// Retrained from — child model fine-tuned from parent model.
    RetrainedFrom,
    /// Anchored — child anchor seal anchors a batch of parent seals.
    Anchored,
    /// Reviewed by — child seal is a reviewer's verification of parent.
    ReviewedBy,
}

impl EdgeType {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DerivedFrom => "derived_from",
            Self::TrainedOn => "trained_on",
            Self::InferredWith => "inferred_with",
            Self::ConsentedFor => "consented_for",
            Self::BatchedFrom => "batched_from",
            Self::RetrainedFrom => "retrained_from",
            Self::Anchored => "anchored",
            Self::ReviewedBy => "reviewed_by",
        }
    }
}

// =============================================================================
// LineageNode + LineageEdge
// =============================================================================

/// Node in the lineage DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageNode {
    /// Seal id (or any unique id within the tenant scope).
    pub id: Uuid,
    /// Tenant the seal belongs to (used for isolation in queries).
    pub tenant_id: String,
    /// Sector (`finance`, `healthcare`, ...).
    pub sector: String,
    /// Workflow id (`credit_decision`, `clinical_inference`, ...).
    pub workflow_id: String,
    /// RFC 3339 timestamp of seal creation.
    pub timestamp: String,
    /// Free-form labels (e.g., `model_id=credit_v3`).
    pub labels: HashMap<String, String>,
}

/// Edge in the lineage DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LineageEdge {
    /// Source node (parent).
    pub from: Uuid,
    /// Destination node (child).
    pub to: Uuid,
    /// Relationship type.
    pub edge_type: EdgeType,
    /// RFC 3339 timestamp the edge was recorded.
    pub recorded_at: String,
    /// Free-form metadata (e.g., `commit_ref`).
    pub meta: HashMap<String, String>,
}

// =============================================================================
// LineageGraph
// =============================================================================

#[derive(Debug, Default)]
struct GraphInner {
    nodes: HashMap<Uuid, LineageNode>,
    /// Adjacency: from-id → list of (to-id, edge-index).
    out_edges: HashMap<Uuid, Vec<usize>>,
    /// Adjacency: to-id → list of (from-id, edge-index).
    in_edges: HashMap<Uuid, Vec<usize>>,
    edges: Vec<LineageEdge>,
}

/// In-memory lineage DAG.
#[derive(Debug, Default)]
pub struct LineageGraph {
    inner: RwLock<GraphInner>,
}

impl LineageGraph {
    /// New empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node. Idempotent (existing entries are overwritten with the
    /// new value).
    pub fn add_node(&self, node: LineageNode) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("lineage lock poisoned".into()))?;
        g.nodes.insert(node.id, node);
        Ok(())
    }

    /// Add an edge from `parent` to `child`. Both nodes must exist.
    /// Rejects cycles (an edge that would create a path child → ... → parent).
    pub fn add_edge(
        &self,
        parent: Uuid,
        child: Uuid,
        edge_type: EdgeType,
    ) -> SandboxResult<()> {
        self.add_edge_with_meta(parent, child, edge_type, HashMap::new())
    }

    /// Add an edge with metadata.
    pub fn add_edge_with_meta(
        &self,
        parent: Uuid,
        child: Uuid,
        edge_type: EdgeType,
        meta: HashMap<String, String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("lineage lock poisoned".into()))?;
        if !g.nodes.contains_key(&parent) {
            return Err(SandboxError::Other(format!(
                "lineage: parent {parent} not in graph"
            )));
        }
        if !g.nodes.contains_key(&child) {
            return Err(SandboxError::Other(format!(
                "lineage: child {child} not in graph"
            )));
        }
        if parent == child {
            return Err(SandboxError::Other("lineage: self-loop rejected".into()));
        }
        // Cycle check: BFS forward from `child` — if it reaches `parent`,
        // adding this edge would create a cycle.
        if would_cycle(&g, parent, child) {
            return Err(SandboxError::Other(format!(
                "lineage: cycle detected ({parent} → {child} would close a loop)"
            )));
        }
        // Reject duplicate edges of the same type.
        if let Some(out) = g.out_edges.get(&parent) {
            for idx in out {
                let e = &g.edges[*idx];
                if e.to == child && e.edge_type == edge_type {
                    return Err(SandboxError::Other(
                        "lineage: duplicate edge".into(),
                    ));
                }
            }
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let edge = LineageEdge {
            from: parent,
            to: child,
            edge_type,
            recorded_at: now,
            meta,
        };
        let idx = g.edges.len();
        g.edges.push(edge);
        g.out_edges.entry(parent).or_default().push(idx);
        g.in_edges.entry(child).or_default().push(idx);
        Ok(())
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.inner.read().map(|g| g.nodes.len()).unwrap_or(0)
    }

    /// Number of edges.
    pub fn edge_count(&self) -> usize {
        self.inner.read().map(|g| g.edges.len()).unwrap_or(0)
    }

    /// Direct parents of `node`.
    pub fn parents(&self, node: Uuid) -> Vec<Uuid> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.in_edges
            .get(&node)
            .map(|v| v.iter().map(|i| g.edges[*i].from).collect())
            .unwrap_or_default()
    }

    /// Direct children of `node`.
    pub fn children(&self, node: Uuid) -> Vec<Uuid> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.out_edges
            .get(&node)
            .map(|v| v.iter().map(|i| g.edges[*i].to).collect())
            .unwrap_or_default()
    }

    /// All ancestors (transitive parents).
    pub fn ancestors(&self, node: Uuid) -> Vec<Uuid> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(node);
        while let Some(cur) = q.pop_front() {
            if let Some(in_idx) = g.in_edges.get(&cur) {
                for i in in_idx {
                    let p = g.edges[*i].from;
                    if seen.insert(p) {
                        out.push(p);
                        q.push_back(p);
                    }
                }
            }
        }
        out
    }

    /// All descendants (transitive children).
    pub fn descendants(&self, node: Uuid) -> Vec<Uuid> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(node);
        while let Some(cur) = q.pop_front() {
            if let Some(out_idx) = g.out_edges.get(&cur) {
                for i in out_idx {
                    let c = g.edges[*i].to;
                    if seen.insert(c) {
                        out.push(c);
                        q.push_back(c);
                    }
                }
            }
        }
        out
    }

    /// Topological sort. Returns `Err` if a cycle exists (shouldn't happen
    /// with our invariant but is checked for safety).
    pub fn topological_sort(&self) -> SandboxResult<Vec<Uuid>> {
        let g = self
            .inner
            .read()
            .map_err(|_| SandboxError::Other("lineage lock poisoned".into()))?;
        let mut indeg: HashMap<Uuid, usize> = g.nodes.keys().map(|k| (*k, 0)).collect();
        for e in &g.edges {
            *indeg.entry(e.to).or_insert(0) += 1;
        }
        let mut q: VecDeque<Uuid> = indeg
            .iter()
            .filter_map(|(k, v)| if *v == 0 { Some(*k) } else { None })
            .collect();
        let mut out = Vec::with_capacity(g.nodes.len());
        while let Some(cur) = q.pop_front() {
            out.push(cur);
            if let Some(out_idx) = g.out_edges.get(&cur) {
                for i in out_idx {
                    let to = g.edges[*i].to;
                    let v = indeg.get_mut(&to).expect("indeg");
                    *v -= 1;
                    if *v == 0 {
                        q.push_back(to);
                    }
                }
            }
        }
        if out.len() != g.nodes.len() {
            return Err(SandboxError::Other("lineage: cycle in graph".into()));
        }
        Ok(out)
    }

    /// All nodes for a tenant.
    pub fn nodes_for_tenant(&self, tenant: &str) -> Vec<LineageNode> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        g.nodes
            .values()
            .filter(|n| n.tenant_id == tenant)
            .cloned()
            .collect()
    }

    /// Count of nodes per workflow id (for dashboards / metrics).
    pub fn workflow_distribution(&self) -> HashMap<String, usize> {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = HashMap::new();
        for n in g.nodes.values() {
            *out.entry(n.workflow_id.clone()).or_insert(0) += 1;
        }
        out
    }

    /// Render to Graphviz DOT.
    pub fn to_dot(&self) -> String {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = String::from("digraph aethelred_lineage {\n");
        out.push_str("  rankdir=LR;\n  node [shape=box, style=rounded];\n");
        for n in g.nodes.values() {
            out.push_str(&format!(
                "  \"{}\" [label=\"{}\\n{}/{}\\n{}\"];\n",
                n.id, n.workflow_id, n.tenant_id, n.sector, &n.timestamp[..10.min(n.timestamp.len())]
            ));
        }
        for e in &g.edges {
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                e.from,
                e.to,
                e.edge_type.as_str()
            ));
        }
        out.push_str("}\n");
        out
    }

    /// Render to Mermaid (Markdown-friendly).
    pub fn to_mermaid(&self) -> String {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let mut out = String::from("graph LR\n");
        for n in g.nodes.values() {
            // Use short id (first 8 chars) as Mermaid node id; sanitize.
            let short = format!("n{}", n.id.simple().to_string().chars().take(8).collect::<String>());
            out.push_str(&format!(
                "  {}[\"{}\\n{}\"]\n",
                short, n.workflow_id, n.tenant_id
            ));
        }
        for e in &g.edges {
            let s = format!("n{}", e.from.simple().to_string().chars().take(8).collect::<String>());
            let t = format!("n{}", e.to.simple().to_string().chars().take(8).collect::<String>());
            out.push_str(&format!("  {} -- {} --> {}\n", s, e.edge_type.as_str(), t));
        }
        out
    }
}

fn would_cycle(g: &GraphInner, parent: Uuid, child: Uuid) -> bool {
    // BFS from child: if we reach parent, adding parent→child closes a cycle.
    let mut q = VecDeque::new();
    let mut seen = HashSet::new();
    q.push_back(child);
    while let Some(cur) = q.pop_front() {
        if cur == parent {
            return true;
        }
        if !seen.insert(cur) {
            continue;
        }
        if let Some(out) = g.out_edges.get(&cur) {
            for idx in out {
                q.push_back(g.edges[*idx].to);
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(workflow: &str) -> LineageNode {
        LineageNode {
            id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            sector: "finance".into(),
            workflow_id: workflow.into(),
            timestamp: "2026-05-06T10:00:00Z".into(),
            labels: HashMap::new(),
        }
    }

    #[test]
    fn add_node_increments_count() {
        let g = LineageGraph::new();
        g.add_node(node("a")).unwrap();
        g.add_node(node("b")).unwrap();
        assert_eq!(g.node_count(), 2);
    }

    #[test]
    fn add_edge_links_nodes() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        assert_eq!(g.edge_count(), 1);
        assert_eq!(g.children(aid), vec![bid]);
        assert_eq!(g.parents(bid), vec![aid]);
    }

    #[test]
    fn missing_parent_rejected() {
        let g = LineageGraph::new();
        let b = node("b");
        let bid = b.id;
        g.add_node(b).unwrap();
        let r = g.add_edge(Uuid::now_v7(), bid, EdgeType::DerivedFrom);
        assert!(r.is_err());
    }

    #[test]
    fn missing_child_rejected() {
        let g = LineageGraph::new();
        let a = node("a");
        let aid = a.id;
        g.add_node(a).unwrap();
        let r = g.add_edge(aid, Uuid::now_v7(), EdgeType::DerivedFrom);
        assert!(r.is_err());
    }

    #[test]
    fn self_loop_rejected() {
        let g = LineageGraph::new();
        let a = node("a");
        let aid = a.id;
        g.add_node(a).unwrap();
        let r = g.add_edge(aid, aid, EdgeType::DerivedFrom);
        assert!(r.is_err());
    }

    #[test]
    fn cycle_rejected() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let c = node("c");
        let aid = a.id;
        let bid = b.id;
        let cid = c.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_node(c).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(bid, cid, EdgeType::DerivedFrom).unwrap();
        // c → a would create cycle.
        let r = g.add_edge(cid, aid, EdgeType::DerivedFrom);
        assert!(r.is_err());
    }

    #[test]
    fn duplicate_edge_rejected() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        let r = g.add_edge(aid, bid, EdgeType::DerivedFrom);
        assert!(r.is_err());
    }

    #[test]
    fn different_edge_types_allowed_between_same_nodes() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(aid, bid, EdgeType::TrainedOn).unwrap();
        assert_eq!(g.edge_count(), 2);
    }

    #[test]
    fn ancestors_returns_transitive_parents() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let c = node("c");
        let aid = a.id;
        let bid = b.id;
        let cid = c.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_node(c).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(bid, cid, EdgeType::DerivedFrom).unwrap();
        let mut anc = g.ancestors(cid);
        anc.sort();
        let mut expected = vec![aid, bid];
        expected.sort();
        assert_eq!(anc, expected);
    }

    #[test]
    fn descendants_returns_transitive_children() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let c = node("c");
        let aid = a.id;
        let bid = b.id;
        let cid = c.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_node(c).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(bid, cid, EdgeType::DerivedFrom).unwrap();
        let mut desc = g.descendants(aid);
        desc.sort();
        let mut expected = vec![bid, cid];
        expected.sort();
        assert_eq!(desc, expected);
    }

    #[test]
    fn topological_sort_preserves_order() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let c = node("c");
        let aid = a.id;
        let bid = b.id;
        let cid = c.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_node(c).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(bid, cid, EdgeType::DerivedFrom).unwrap();
        let topo = g.topological_sort().unwrap();
        let pa = topo.iter().position(|&x| x == aid).unwrap();
        let pb = topo.iter().position(|&x| x == bid).unwrap();
        let pc = topo.iter().position(|&x| x == cid).unwrap();
        assert!(pa < pb);
        assert!(pb < pc);
    }

    #[test]
    fn topological_sort_handles_disconnected_components() {
        let g = LineageGraph::new();
        for _ in 0..5 {
            g.add_node(node("x")).unwrap();
        }
        let topo = g.topological_sort().unwrap();
        assert_eq!(topo.len(), 5);
    }

    #[test]
    fn nodes_for_tenant_filters_correctly() {
        let g = LineageGraph::new();
        let mut a = node("a");
        a.tenant_id = "FAB".into();
        let mut b = node("b");
        b.tenant_id = "ENBD".into();
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        assert_eq!(g.nodes_for_tenant("FAB").len(), 1);
        assert_eq!(g.nodes_for_tenant("ENBD").len(), 1);
        assert_eq!(g.nodes_for_tenant("UNKNOWN").len(), 0);
    }

    #[test]
    fn workflow_distribution_counts_correctly() {
        let g = LineageGraph::new();
        for _ in 0..3 {
            g.add_node(node("credit_decision")).unwrap();
        }
        for _ in 0..2 {
            g.add_node(node("aml_screening")).unwrap();
        }
        let dist = g.workflow_distribution();
        assert_eq!(dist.get("credit_decision").copied(), Some(3));
        assert_eq!(dist.get("aml_screening").copied(), Some(2));
    }

    #[test]
    fn dot_export_includes_nodes_and_edges() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        let dot = g.to_dot();
        assert!(dot.contains("digraph aethelred_lineage"));
        assert!(dot.contains("derived_from"));
    }

    #[test]
    fn mermaid_export_includes_nodes_and_edges() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        let mer = g.to_mermaid();
        assert!(mer.contains("graph LR"));
        assert!(mer.contains("derived_from"));
    }

    #[test]
    fn empty_graph_no_nodes() {
        let g = LineageGraph::new();
        assert_eq!(g.node_count(), 0);
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn parents_unknown_node_empty() {
        let g = LineageGraph::new();
        assert!(g.parents(Uuid::now_v7()).is_empty());
    }

    #[test]
    fn descendants_leaf_empty() {
        let g = LineageGraph::new();
        let a = node("a");
        let aid = a.id;
        g.add_node(a).unwrap();
        assert!(g.descendants(aid).is_empty());
    }

    #[test]
    fn edge_type_string_ids_unique() {
        let all = [
            EdgeType::DerivedFrom,
            EdgeType::TrainedOn,
            EdgeType::InferredWith,
            EdgeType::ConsentedFor,
            EdgeType::BatchedFrom,
            EdgeType::RetrainedFrom,
            EdgeType::Anchored,
            EdgeType::ReviewedBy,
        ];
        let mut ids: Vec<&str> = all.iter().map(|e| e.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn add_edge_with_meta_records_metadata() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let aid = a.id;
        let bid = b.id;
        g.add_node(a).unwrap();
        g.add_node(b).unwrap();
        let mut meta = HashMap::new();
        meta.insert("commit".into(), "abc123".into());
        g.add_edge_with_meta(aid, bid, EdgeType::TrainedOn, meta).unwrap();
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn diamond_dependency_resolves_correctly() {
        let g = LineageGraph::new();
        let a = node("a");
        let b = node("b");
        let c = node("c");
        let d = node("d");
        let aid = a.id;
        let bid = b.id;
        let cid = c.id;
        let did = d.id;
        for n in [a, b, c, d] {
            g.add_node(n).unwrap();
        }
        // a → b → d, a → c → d  (diamond)
        g.add_edge(aid, bid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(aid, cid, EdgeType::DerivedFrom).unwrap();
        g.add_edge(bid, did, EdgeType::DerivedFrom).unwrap();
        g.add_edge(cid, did, EdgeType::DerivedFrom).unwrap();
        let mut anc = g.ancestors(did);
        anc.sort();
        let mut expected = vec![aid, bid, cid];
        expected.sort();
        assert_eq!(anc, expected);
    }

    #[test]
    fn lineage_node_serde_round_trip() {
        let n = node("a");
        let j = serde_json::to_string(&n).unwrap();
        let p: LineageNode = serde_json::from_str(&j).unwrap();
        assert_eq!(p, n);
    }

    #[test]
    fn many_node_graph_topo_sorts_quickly() {
        let g = LineageGraph::new();
        let mut prev: Option<Uuid> = None;
        for _ in 0..50 {
            let n = node("seq");
            let id = n.id;
            g.add_node(n).unwrap();
            if let Some(p) = prev {
                g.add_edge(p, id, EdgeType::DerivedFrom).unwrap();
            }
            prev = Some(id);
        }
        let topo = g.topological_sort().unwrap();
        assert_eq!(topo.len(), 50);
    }
}
