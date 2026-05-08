//! Dataset lineage — which datasets fed which models.
//!
//! Distinct from [`crate::lineage`] (general-purpose graph) and
//! [`crate::feature_store_provenance`] (per-decision feature lookup).
//! This module is the upstream artifact graph: dataset versions →
//! transformations → model training runs.
//!
//! Auditors ask "which datasets contributed to this model?" — this module
//! answers in a single typed traversal.

use crate::hashing::Sha256Digest;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;

// =============================================================================
// DatasetId / DatasetVersion
// =============================================================================

/// Stable id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DatasetId(pub String);

impl DatasetId {
    /// New.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    /// `&str`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One dataset version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatasetVersion {
    /// Dataset id.
    pub dataset_id: DatasetId,
    /// Version label.
    pub version: String,
    /// SHA-256 of contents.
    pub content_hash: Sha256Digest,
    /// Owner.
    pub owner: String,
    /// RFC 3339 captured at.
    pub captured_at: String,
    /// Sample count.
    pub sample_count: Option<u64>,
    /// Schema label (for cross-version comparison).
    pub schema_label: String,
}

// =============================================================================
// ModelArtifactId
// =============================================================================

/// Model artifact id (model + version).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelArtifactId {
    /// Model id.
    pub model_id: String,
    /// Version.
    pub version: String,
}

// =============================================================================
// LineageEdge
// =============================================================================

/// Edge label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageEdgeLabel {
    /// Dataset version → transformed dataset version.
    TransformedFrom,
    /// Dataset version → model artifact (used in training).
    UsedForTraining,
    /// Dataset version → model artifact (used in evaluation).
    UsedForEvaluation,
}

/// One typed edge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct LineageEdge {
    /// Source dataset version key (`"id@version"`).
    pub from: String,
    /// Target (dataset version key or `"model:id@version"`).
    pub to: String,
    /// Label.
    pub label: LineageEdgeLabel,
}

// =============================================================================
// DatasetLineage
// =============================================================================

#[derive(Default)]
struct State {
    /// `"id@version"` → version record.
    versions: HashMap<String, DatasetVersion>,
    /// `"model:id@version"` → ModelArtifactId.
    models: HashMap<String, ModelArtifactId>,
    /// Edges out (source → set of edges).
    edges_out: HashMap<String, HashSet<LineageEdge>>,
    /// Edges in (target → set of edges).
    edges_in: HashMap<String, HashSet<LineageEdge>>,
}

/// Lineage registry.
pub struct DatasetLineage {
    state: RwLock<State>,
}

impl Default for DatasetLineage {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for DatasetLineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatasetLineage")
            .field("versions", &self.dataset_count())
            .field("models", &self.model_count())
            .finish()
    }
}

impl DatasetLineage {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a dataset version. Errors on duplicate (id@version).
    pub fn add_dataset_version(&self, v: DatasetVersion) -> SandboxResult<()> {
        let key = dv_key(&v.dataset_id, &v.version);
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("lineage poisoned".into()))?;
        if g.versions.contains_key(&key) {
            return Err(SandboxError::Other(format!(
                "dataset version {} already registered",
                key
            )));
        }
        g.versions.insert(key, v);
        Ok(())
    }

    /// Register a model artifact.
    pub fn add_model(&self, m: ModelArtifactId) -> SandboxResult<()> {
        let key = mk_key(&m);
        self.state
            .write()
            .map_err(|_| SandboxError::Other("lineage poisoned".into()))?
            .models
            .insert(key, m);
        Ok(())
    }

    /// Add an edge.
    pub fn add_edge(&self, e: LineageEdge) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("lineage poisoned".into()))?;
        if !g.versions.contains_key(&e.from) && !g.models.contains_key(&e.from) {
            return Err(SandboxError::Other(format!(
                "edge source {} unknown",
                e.from
            )));
        }
        if !g.versions.contains_key(&e.to) && !g.models.contains_key(&e.to) {
            return Err(SandboxError::Other(format!(
                "edge target {} unknown",
                e.to
            )));
        }
        g.edges_out.entry(e.from.clone()).or_default().insert(e.clone());
        g.edges_in.entry(e.to.clone()).or_default().insert(e);
        Ok(())
    }

    /// Datasets used (transitively) for training a model.
    pub fn datasets_for_model(&self, m: &ModelArtifactId) -> Vec<DatasetVersion> {
        let key = mk_key(m);
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut visited: HashSet<String> = HashSet::new();
        let mut q: VecDeque<String> = VecDeque::new();
        q.push_back(key);
        while let Some(n) = q.pop_front() {
            if !visited.insert(n.clone()) {
                continue;
            }
            if let Some(in_edges) = g.edges_in.get(&n) {
                for e in in_edges {
                    q.push_back(e.from.clone());
                }
            }
        }
        visited
            .into_iter()
            .filter_map(|k| g.versions.get(&k).cloned())
            .collect()
    }

    /// Models trained on a dataset version (transitively forward).
    pub fn models_from_dataset(&self, id: &DatasetId, version: &str) -> Vec<ModelArtifactId> {
        let key = dv_key(id, version);
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut visited: HashSet<String> = HashSet::new();
        let mut q: VecDeque<String> = VecDeque::new();
        q.push_back(key);
        while let Some(n) = q.pop_front() {
            if !visited.insert(n.clone()) {
                continue;
            }
            if let Some(out) = g.edges_out.get(&n) {
                for e in out {
                    q.push_back(e.to.clone());
                }
            }
        }
        visited
            .into_iter()
            .filter_map(|k| g.models.get(&k).cloned())
            .collect()
    }

    /// Lookup dataset version.
    pub fn dataset(&self, id: &DatasetId, version: &str) -> Option<DatasetVersion> {
        self.state
            .read()
            .ok()?
            .versions
            .get(&dv_key(id, version))
            .cloned()
    }

    /// All edges.
    pub fn edges(&self) -> Vec<LineageEdge> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut v: Vec<LineageEdge> = Vec::new();
        for (_, set) in &g.edges_out {
            for e in set {
                v.push(e.clone());
            }
        }
        v
    }

    /// Dataset count.
    pub fn dataset_count(&self) -> usize {
        self.state.read().map(|g| g.versions.len()).unwrap_or(0)
    }

    /// Model count.
    pub fn model_count(&self) -> usize {
        self.state.read().map(|g| g.models.len()).unwrap_or(0)
    }

    /// Edge count.
    pub fn edge_count(&self) -> usize {
        self.state
            .read()
            .map(|g| g.edges_out.values().map(|s| s.len()).sum())
            .unwrap_or(0)
    }
}

fn dv_key(id: &DatasetId, version: &str) -> String {
    format!("{}@{}", id.as_str(), version)
}
fn mk_key(m: &ModelArtifactId) -> String {
    format!("model:{}@{}", m.model_id, m.version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hasher;

    fn dv(id: &str, version: &str, contents: &[u8]) -> DatasetVersion {
        DatasetVersion {
            dataset_id: DatasetId::new(id),
            version: version.into(),
            content_hash: Hasher::sha256(contents),
            owner: "data-team".into(),
            captured_at: "2026-01-01T00:00:00Z".into(),
            sample_count: Some(1000),
            schema_label: "v1".into(),
        }
    }

    fn m(model: &str, version: &str) -> ModelArtifactId {
        ModelArtifactId {
            model_id: model.into(),
            version: version.into(),
        }
    }

    #[test]
    fn add_dataset_version() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        assert_eq!(l.dataset_count(), 1);
    }

    #[test]
    fn duplicate_version_errors() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        assert!(l.add_dataset_version(dv("d1", "v1", b"y")).is_err());
    }

    #[test]
    fn add_model() {
        let l = DatasetLineage::new();
        l.add_model(m("credit-risk", "1.0")).unwrap();
        assert_eq!(l.model_count(), 1);
    }

    #[test]
    fn add_edge_after_versions() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        l.add_model(m("credit-risk", "1.0")).unwrap();
        let e = LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: mk_key(&m("credit-risk", "1.0")),
            label: LineageEdgeLabel::UsedForTraining,
        };
        l.add_edge(e).unwrap();
        assert_eq!(l.edge_count(), 1);
    }

    #[test]
    fn edge_to_unknown_errors() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        let e = LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: "missing".into(),
            label: LineageEdgeLabel::UsedForTraining,
        };
        assert!(l.add_edge(e).is_err());
    }

    #[test]
    fn datasets_for_model_traverses() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        l.add_dataset_version(dv("d2", "v1", b"y")).unwrap();
        l.add_model(m("credit-risk", "1.0")).unwrap();
        // d1 → d2 (transformed) → model.
        l.add_edge(LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: dv_key(&DatasetId::new("d2"), "v1"),
            label: LineageEdgeLabel::TransformedFrom,
        })
        .unwrap();
        l.add_edge(LineageEdge {
            from: dv_key(&DatasetId::new("d2"), "v1"),
            to: mk_key(&m("credit-risk", "1.0")),
            label: LineageEdgeLabel::UsedForTraining,
        })
        .unwrap();
        let datasets = l.datasets_for_model(&m("credit-risk", "1.0"));
        assert_eq!(datasets.len(), 2);
    }

    #[test]
    fn models_from_dataset_traverses() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        l.add_model(m("a", "1.0")).unwrap();
        l.add_model(m("b", "1.0")).unwrap();
        l.add_edge(LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: mk_key(&m("a", "1.0")),
            label: LineageEdgeLabel::UsedForTraining,
        })
        .unwrap();
        l.add_edge(LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: mk_key(&m("b", "1.0")),
            label: LineageEdgeLabel::UsedForEvaluation,
        })
        .unwrap();
        let models = l.models_from_dataset(&DatasetId::new("d1"), "v1");
        assert_eq!(models.len(), 2);
    }

    #[test]
    fn dataset_lookup() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        assert!(l.dataset(&DatasetId::new("d1"), "v1").is_some());
        assert!(l.dataset(&DatasetId::new("d1"), "v2").is_none());
    }

    #[test]
    fn version_serde() {
        let v = dv("d1", "v1", b"x");
        let j = serde_json::to_string(&v).unwrap();
        let p: DatasetVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(p, v);
    }

    #[test]
    fn model_id_serde() {
        let mm = m("x", "y");
        let j = serde_json::to_string(&mm).unwrap();
        let p: ModelArtifactId = serde_json::from_str(&j).unwrap();
        assert_eq!(p, mm);
    }

    #[test]
    fn edge_label_serde() {
        for l in [
            LineageEdgeLabel::TransformedFrom,
            LineageEdgeLabel::UsedForTraining,
            LineageEdgeLabel::UsedForEvaluation,
        ] {
            let j = serde_json::to_string(&l).unwrap();
            let p: LineageEdgeLabel = serde_json::from_str(&j).unwrap();
            assert_eq!(p, l);
        }
    }

    #[test]
    fn dataset_id_serde_transparent() {
        let id = DatasetId::new("x");
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"x\"");
    }

    #[test]
    fn edges_returns_all() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        l.add_model(m("a", "1")).unwrap();
        l.add_edge(LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: mk_key(&m("a", "1")),
            label: LineageEdgeLabel::UsedForTraining,
        })
        .unwrap();
        assert_eq!(l.edges().len(), 1);
    }

    #[test]
    fn empty_traversal_yields_empty() {
        let l = DatasetLineage::new();
        assert!(l.datasets_for_model(&m("ghost", "1")).is_empty());
    }

    #[test]
    fn duplicate_edge_dedupes() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        l.add_model(m("a", "1")).unwrap();
        let e = LineageEdge {
            from: dv_key(&DatasetId::new("d1"), "v1"),
            to: mk_key(&m("a", "1")),
            label: LineageEdgeLabel::UsedForTraining,
        };
        l.add_edge(e.clone()).unwrap();
        l.add_edge(e).unwrap();
        assert_eq!(l.edge_count(), 1);
    }

    #[test]
    fn diamond_lineage() {
        let l = DatasetLineage::new();
        // d1 splits into d2a and d2b, both feed model.
        for v in &["d1", "d2a", "d2b"] {
            l.add_dataset_version(dv(*v, "v1", b"x")).unwrap();
        }
        l.add_model(m("model", "1")).unwrap();
        for split in &["d2a", "d2b"] {
            l.add_edge(LineageEdge {
                from: dv_key(&DatasetId::new("d1"), "v1"),
                to: dv_key(&DatasetId::new(*split), "v1"),
                label: LineageEdgeLabel::TransformedFrom,
            })
            .unwrap();
            l.add_edge(LineageEdge {
                from: dv_key(&DatasetId::new(*split), "v1"),
                to: mk_key(&m("model", "1")),
                label: LineageEdgeLabel::UsedForTraining,
            })
            .unwrap();
        }
        let datasets = l.datasets_for_model(&m("model", "1"));
        assert_eq!(datasets.len(), 3);
    }

    #[test]
    fn many_models_per_dataset() {
        let l = DatasetLineage::new();
        l.add_dataset_version(dv("d1", "v1", b"x")).unwrap();
        for i in 0..10 {
            l.add_model(m(&format!("m{i}"), "1")).unwrap();
            l.add_edge(LineageEdge {
                from: dv_key(&DatasetId::new("d1"), "v1"),
                to: mk_key(&m(&format!("m{i}"), "1")),
                label: LineageEdgeLabel::UsedForTraining,
            })
            .unwrap();
        }
        assert_eq!(l.models_from_dataset(&DatasetId::new("d1"), "v1").len(), 10);
    }

    #[test]
    fn model_count_tracks() {
        let l = DatasetLineage::new();
        assert_eq!(l.model_count(), 0);
        l.add_model(m("x", "1")).unwrap();
        assert_eq!(l.model_count(), 1);
    }

    #[test]
    fn schema_label_recorded() {
        let mut v = dv("d", "1", b"x");
        v.schema_label = "v3.1".into();
        let l = DatasetLineage::new();
        l.add_dataset_version(v.clone()).unwrap();
        let got = l.dataset(&DatasetId::new("d"), "1").unwrap();
        assert_eq!(got.schema_label, "v3.1");
    }
}
