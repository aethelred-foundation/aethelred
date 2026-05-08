//! Feature-store provenance — per-decision feature lineage.
//!
//! Every model decision is conditional on the *exact feature values* that
//! were materialized for that request. When auditors ask "what did the
//! model see when it denied this loan?" the operator must answer with
//! cryptographic specificity: which features, sourced from which datasets,
//! at which version, fetched at what time, with which transformation.
//!
//! ## Model
//!
//! - [`FeatureSnapshot`] — one feature's `(name, value, source, version)`
//!   captured at decision time.
//! - [`FeatureBatch`] — all features for one decision, content-addressed by
//!   their concatenated hash.
//! - [`FeatureProvenanceLog`] — append-only batches keyed by decision id.
//!
//! Per-feature snapshots are *hashed*, not stored raw, when sensitivity
//! requires (the `value` is omitted and only the hash is kept). That makes
//! the log safe to share with auditors who shouldn't see the raw PII.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// FeatureSource
// =============================================================================

/// Origin of a feature value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureSource {
    /// Source name (e.g. `"feast.online_store"`, `"opendata.census_2024"`).
    pub name: String,
    /// Source version (semver, commit hash, or dataset version).
    pub version: String,
    /// Optional URI for forensic re-fetch.
    pub uri: Option<String>,
}

// =============================================================================
// FeatureSnapshot
// =============================================================================

/// One feature's captured value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureSnapshot {
    /// Feature name.
    pub name: String,
    /// Stored value (free-text representation; may be empty if redacted).
    pub value: String,
    /// `true` if `value` was redacted (only `value_hash` is meaningful).
    pub redacted: bool,
    /// SHA-256 of the original value bytes.
    pub value_hash: Sha256Digest,
    /// Source.
    pub source: FeatureSource,
    /// RFC 3339 fetch time.
    pub fetched_at: String,
    /// Optional transformation chain (e.g. `["normalize", "log1p"]`).
    pub transformations: Vec<String>,
}

impl FeatureSnapshot {
    /// New snapshot from raw value.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        source: FeatureSource,
    ) -> Self {
        let value = value.into();
        let value_hash = Hasher::sha256(value.as_bytes());
        Self {
            name: name.into(),
            value,
            redacted: false,
            value_hash,
            source,
            fetched_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            transformations: Vec::new(),
        }
    }

    /// Hash the value and clear the raw bytes (PII-safe).
    pub fn redact(mut self) -> Self {
        self.redacted = true;
        self.value = String::new();
        self
    }

    /// Builder: add a transformation step.
    pub fn with_transformation(mut self, step: impl Into<String>) -> Self {
        self.transformations.push(step.into());
        self
    }
}

// =============================================================================
// FeatureBatch
// =============================================================================

/// Per-decision bundle of features.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureBatch {
    /// Batch id.
    pub batch_id: Uuid,
    /// The decision id this batch served.
    pub decision_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Feature snapshots, sorted by name.
    pub features: Vec<FeatureSnapshot>,
    /// Aggregate hash of all feature value-hashes.
    pub batch_hash: Sha256Digest,
    /// RFC 3339 batch creation.
    pub created_at: String,
}

impl FeatureBatch {
    /// Build a batch from a list of snapshots (auto-sorts).
    pub fn build(
        decision_id: impl Into<String>,
        tenant: impl Into<String>,
        mut features: Vec<FeatureSnapshot>,
    ) -> Self {
        features.sort_by(|a, b| a.name.cmp(&b.name));
        let mut input = Vec::new();
        for f in &features {
            input.extend_from_slice(f.name.as_bytes());
            input.push(0);
            input.extend_from_slice(&f.value_hash.0);
        }
        let batch_hash = Hasher::sha256(&input);
        Self {
            batch_id: Uuid::now_v7(),
            decision_id: decision_id.into(),
            tenant_id: tenant.into(),
            features,
            batch_hash,
            created_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    /// Find a feature by name.
    pub fn find(&self, name: &str) -> Option<&FeatureSnapshot> {
        self.features.iter().find(|f| f.name == name)
    }

    /// Number of features.
    pub fn feature_count(&self) -> usize {
        self.features.len()
    }
}

// =============================================================================
// FeatureProvenanceLog
// =============================================================================

#[derive(Default)]
struct LogState {
    batches: HashMap<String, FeatureBatch>,
}

/// Append-only log keyed by decision_id.
pub struct FeatureProvenanceLog {
    state: RwLock<LogState>,
}

impl Default for FeatureProvenanceLog {
    fn default() -> Self {
        Self {
            state: RwLock::new(LogState::default()),
        }
    }
}

impl std::fmt::Debug for FeatureProvenanceLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureProvenanceLog")
            .field("batches", &self.len())
            .finish()
    }
}

impl FeatureProvenanceLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a batch. Errors if `decision_id` already exists.
    pub fn append(&self, batch: FeatureBatch) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("provenance log poisoned".into()))?;
        if g.batches.contains_key(&batch.decision_id) {
            return Err(SandboxError::Other(format!(
                "decision {} already has provenance",
                batch.decision_id
            )));
        }
        g.batches.insert(batch.decision_id.clone(), batch);
        Ok(())
    }

    /// Look up by decision id.
    pub fn lookup(&self, decision_id: &str) -> Option<FeatureBatch> {
        self.state.read().ok()?.batches.get(decision_id).cloned()
    }

    /// Number of batches recorded.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.batches.len()).unwrap_or(0)
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Filter batches that include a feature with the given hash. Useful
    /// for "find every decision that used this exact feature value".
    pub fn batches_with_feature_hash(&self, h: &Sha256Digest) -> Vec<FeatureBatch> {
        self.state
            .read()
            .map(|g| {
                g.batches
                    .values()
                    .filter(|b| b.features.iter().any(|f| &f.value_hash == h))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Verify the integrity of one batch: recompute `batch_hash` from
    /// features and compare.
    pub fn verify(&self, decision_id: &str) -> SandboxResult<()> {
        let b = self.lookup(decision_id).ok_or_else(|| {
            SandboxError::Other(format!("decision {} not found", decision_id))
        })?;
        let mut input = Vec::new();
        let mut features = b.features.clone();
        features.sort_by(|a, b| a.name.cmp(&b.name));
        for f in &features {
            input.extend_from_slice(f.name.as_bytes());
            input.push(0);
            input.extend_from_slice(&f.value_hash.0);
        }
        let recomputed = Hasher::sha256(&input);
        if recomputed != b.batch_hash {
            return Err(SandboxError::Other(format!(
                "batch hash mismatch for decision {}",
                decision_id
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> FeatureSource {
        FeatureSource {
            name: "feast".into(),
            version: "1.0".into(),
            uri: Some("feast://x".into()),
        }
    }

    #[test]
    fn snapshot_records_hash() {
        let s = FeatureSnapshot::new("income", "42000", src());
        assert_eq!(s.value_hash, Hasher::sha256(b"42000"));
        assert!(!s.redacted);
    }

    #[test]
    fn redact_clears_value_keeps_hash() {
        let s = FeatureSnapshot::new("income", "42000", src()).redact();
        assert!(s.redacted);
        assert_eq!(s.value, "");
        assert_eq!(s.value_hash, Hasher::sha256(b"42000"));
    }

    #[test]
    fn transformations_preserved() {
        let s = FeatureSnapshot::new("score", "3.5", src())
            .with_transformation("normalize")
            .with_transformation("log1p");
        assert_eq!(s.transformations, vec!["normalize", "log1p"]);
    }

    #[test]
    fn batch_sorts_features_by_name() {
        let b = FeatureBatch::build(
            "d1",
            "FAB",
            vec![
                FeatureSnapshot::new("zebra", "z", src()),
                FeatureSnapshot::new("apple", "a", src()),
                FeatureSnapshot::new("banana", "b", src()),
            ],
        );
        assert_eq!(b.features[0].name, "apple");
        assert_eq!(b.features[2].name, "zebra");
    }

    #[test]
    fn batch_hash_deterministic() {
        let b1 = FeatureBatch::build(
            "d1",
            "FAB",
            vec![
                FeatureSnapshot::new("a", "1", src()),
                FeatureSnapshot::new("b", "2", src()),
            ],
        );
        let b2 = FeatureBatch::build(
            "d1",
            "FAB",
            vec![
                FeatureSnapshot::new("b", "2", src()),
                FeatureSnapshot::new("a", "1", src()),
            ],
        );
        assert_eq!(b1.batch_hash, b2.batch_hash);
    }

    #[test]
    fn batch_hash_changes_with_value() {
        let b1 = FeatureBatch::build(
            "d1",
            "FAB",
            vec![FeatureSnapshot::new("a", "1", src())],
        );
        let b2 = FeatureBatch::build(
            "d1",
            "FAB",
            vec![FeatureSnapshot::new("a", "2", src())],
        );
        assert_ne!(b1.batch_hash, b2.batch_hash);
    }

    #[test]
    fn log_appends() {
        let l = FeatureProvenanceLog::new();
        let b = FeatureBatch::build("d1", "FAB", vec![]);
        l.append(b).unwrap();
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn log_rejects_duplicate_decision() {
        let l = FeatureProvenanceLog::new();
        let b = FeatureBatch::build("d1", "FAB", vec![]);
        l.append(b.clone()).unwrap();
        assert!(l.append(b).is_err());
    }

    #[test]
    fn lookup_returns_batch() {
        let l = FeatureProvenanceLog::new();
        let b = FeatureBatch::build("d1", "FAB", vec![]);
        l.append(b).unwrap();
        assert!(l.lookup("d1").is_some());
        assert!(l.lookup("missing").is_none());
    }

    #[test]
    fn batches_with_feature_hash_finds_match() {
        let l = FeatureProvenanceLog::new();
        let snap = FeatureSnapshot::new("a", "v1", src());
        let target_hash = snap.value_hash;
        l.append(FeatureBatch::build("d1", "FAB", vec![snap])).unwrap();
        l.append(FeatureBatch::build(
            "d2",
            "FAB",
            vec![FeatureSnapshot::new("a", "v2", src())],
        ))
        .unwrap();
        let matches = l.batches_with_feature_hash(&target_hash);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].decision_id, "d1");
    }

    #[test]
    fn verify_passes_after_append() {
        let l = FeatureProvenanceLog::new();
        l.append(FeatureBatch::build(
            "d1",
            "FAB",
            vec![FeatureSnapshot::new("a", "1", src())],
        ))
        .unwrap();
        l.verify("d1").unwrap();
    }

    #[test]
    fn verify_unknown_errors() {
        let l = FeatureProvenanceLog::new();
        assert!(l.verify("ghost").is_err());
    }

    #[test]
    fn batch_find_returns_feature() {
        let b = FeatureBatch::build(
            "d1",
            "FAB",
            vec![
                FeatureSnapshot::new("a", "1", src()),
                FeatureSnapshot::new("b", "2", src()),
            ],
        );
        assert!(b.find("a").is_some());
        assert!(b.find("missing").is_none());
    }

    #[test]
    fn batch_feature_count() {
        let b = FeatureBatch::build(
            "d1",
            "FAB",
            vec![
                FeatureSnapshot::new("a", "1", src()),
                FeatureSnapshot::new("b", "2", src()),
            ],
        );
        assert_eq!(b.feature_count(), 2);
    }

    #[test]
    fn snapshot_serde_round_trip() {
        let s = FeatureSnapshot::new("a", "v", src()).with_transformation("x");
        let j = serde_json::to_string(&s).unwrap();
        let p: FeatureSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn batch_serde_round_trip() {
        let b = FeatureBatch::build(
            "d1",
            "FAB",
            vec![FeatureSnapshot::new("a", "v", src())],
        );
        let j = serde_json::to_string(&b).unwrap();
        let p: FeatureBatch = serde_json::from_str(&j).unwrap();
        assert_eq!(p, b);
    }

    #[test]
    fn source_serde() {
        let s = src();
        let j = serde_json::to_string(&s).unwrap();
        let p: FeatureSource = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn empty_log_lookup_none() {
        let l = FeatureProvenanceLog::new();
        assert!(l.is_empty());
        assert!(l.lookup("anything").is_none());
    }

    #[test]
    fn many_batches_recorded() {
        let l = FeatureProvenanceLog::new();
        for i in 0..50 {
            let b = FeatureBatch::build(
                format!("d{i}"),
                "FAB",
                vec![FeatureSnapshot::new("x", "1", src())],
            );
            l.append(b).unwrap();
        }
        assert_eq!(l.len(), 50);
    }

    #[test]
    fn redacted_value_hash_unchanged() {
        let s = FeatureSnapshot::new("x", "secret", src());
        let h = s.value_hash;
        let r = s.redact();
        assert_eq!(r.value_hash, h);
    }

    #[test]
    fn batch_hash_deterministic_after_redact() {
        let s1 = FeatureSnapshot::new("x", "v", src());
        let s2 = s1.clone().redact();
        let b1 = FeatureBatch::build("d1", "FAB", vec![s1]);
        let b2 = FeatureBatch::build("d2", "FAB", vec![s2]);
        // Different decision_ids but same feature hashes → same batch_hash
        // since batch_hash only includes features.
        assert_eq!(b1.batch_hash, b2.batch_hash);
    }
}
