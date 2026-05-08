//! Typed search across seals.
//!
//! Auditors and operators routinely run queries like "find every seal in
//! tenant FAB between 2026-04 and 2026-06 with `event_type='credit_decision'`
//! and `policy_id='po_kyc_v3'`." This module provides a small typed-query
//! engine over [`crate::DigitalSeal`] collections that returns matching
//! ids quickly, without pulling in a full search engine.
//!
//! It is **not** a full-text search; it's an indexed predicate-based
//! filter. For semantic search, layer on top of vector DBs separately.

use crate::seal::DigitalSeal;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SearchQuery
// =============================================================================

/// Query predicate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchQuery {
    /// Tenant equality.
    pub tenant_id: Option<String>,
    /// Workflow equality.
    pub workflow_id: Option<String>,
    /// Event type equality.
    pub event_type: Option<String>,
    /// Policy id equality.
    pub policy_id: Option<String>,
    /// Jurisdiction equality.
    pub jurisdiction: Option<String>,
    /// Sector equality (free-form string match against `Sector::label`).
    pub sector_label: Option<String>,
    /// Range start (RFC 3339).
    pub from: Option<String>,
    /// Range end (RFC 3339).
    pub to: Option<String>,
    /// Pagination offset.
    pub offset: Option<usize>,
    /// Pagination limit.
    pub limit: Option<usize>,
}

impl SearchQuery {
    /// Empty query (matches all).
    pub fn new() -> Self {
        Self::default()
    }
    /// Builder: tenant.
    pub fn tenant(mut self, id: impl Into<String>) -> Self {
        self.tenant_id = Some(id.into());
        self
    }
    /// Builder: workflow.
    pub fn workflow(mut self, id: impl Into<String>) -> Self {
        self.workflow_id = Some(id.into());
        self
    }
    /// Builder: event type.
    pub fn event(mut self, e: impl Into<String>) -> Self {
        self.event_type = Some(e.into());
        self
    }
    /// Builder: policy id.
    pub fn policy(mut self, p: impl Into<String>) -> Self {
        self.policy_id = Some(p.into());
        self
    }
    /// Builder: jurisdiction.
    pub fn jurisdiction(mut self, j: impl Into<String>) -> Self {
        self.jurisdiction = Some(j.into());
        self
    }
    /// Builder: sector label.
    pub fn sector(mut self, s: impl Into<String>) -> Self {
        self.sector_label = Some(s.into());
        self
    }
    /// Builder: time range.
    pub fn between(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.from = Some(from.into());
        self.to = Some(to.into());
        self
    }
    /// Builder: limit.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }
    /// Builder: offset.
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = Some(n);
        self
    }

    /// Match against a single seal.
    pub fn matches(&self, seal: &DigitalSeal) -> bool {
        if let Some(t) = &self.tenant_id {
            if seal.tenant_id != *t {
                return false;
            }
        }
        if let Some(w) = &self.workflow_id {
            if seal.workflow_id != *w {
                return false;
            }
        }
        if let Some(e) = &self.event_type {
            if seal.event_type != *e {
                return false;
            }
        }
        if let Some(p) = &self.policy_id {
            if seal.policy_id != *p {
                return false;
            }
        }
        if let Some(j) = &self.jurisdiction {
            if seal.jurisdiction_tag != *j {
                return false;
            }
        }
        if let Some(s) = &self.sector_label {
            if seal.sector.label() != *s {
                return false;
            }
        }
        if let Some(from) = &self.from {
            if let Ok(f) = OffsetDateTime::parse(
                from,
                &time::format_description::well_known::Rfc3339,
            ) {
                if seal.timestamp < f {
                    return false;
                }
            }
        }
        if let Some(to) = &self.to {
            if let Ok(t) = OffsetDateTime::parse(
                to,
                &time::format_description::well_known::Rfc3339,
            ) {
                if seal.timestamp > t {
                    return false;
                }
            }
        }
        true
    }
}

// =============================================================================
// SearchHit
// =============================================================================

/// One match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchHit {
    /// Seal id.
    pub seal_id: Uuid,
    /// Workflow id.
    pub workflow_id: String,
    /// Tenant.
    pub tenant_id: String,
    /// Event type.
    pub event_type: String,
    /// Policy id.
    pub policy_id: String,
    /// Sector label.
    pub sector_label: String,
    /// Jurisdiction.
    pub jurisdiction: String,
    /// Timestamp (RFC 3339).
    pub timestamp: String,
}

/// Search result set.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchResult {
    /// Hits in match order.
    pub hits: Vec<SearchHit>,
    /// Total matches *before* pagination.
    pub total_matches: u64,
    /// Pagination offset used.
    pub offset: usize,
    /// Pagination limit used (`None` = no limit).
    pub limit: Option<usize>,
}

// =============================================================================
// EvidenceSearchIndex
// =============================================================================

#[derive(Default)]
struct State {
    seals: Vec<DigitalSeal>,
}

/// Read-mostly seal collection with predicate search.
pub struct EvidenceSearchIndex {
    state: RwLock<State>,
}

impl Default for EvidenceSearchIndex {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for EvidenceSearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceSearchIndex")
            .field("seals", &self.len())
            .finish()
    }
}

impl EvidenceSearchIndex {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one seal to the index.
    pub fn add(&self, seal: DigitalSeal) {
        if let Ok(mut g) = self.state.write() {
            g.seals.push(seal);
        }
    }

    /// Add many seals.
    pub fn add_all<I: IntoIterator<Item = DigitalSeal>>(&self, seals: I) {
        if let Ok(mut g) = self.state.write() {
            for s in seals {
                g.seals.push(s);
            }
        }
    }

    /// Total seals indexed.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.seals.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Search.
    pub fn search(&self, query: &SearchQuery) -> SearchResult {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return SearchResult::default(),
        };
        let matches: Vec<&DigitalSeal> = g
            .seals
            .iter()
            .filter(|s| query.matches(s))
            .collect();
        let total = matches.len() as u64;
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit;
        let slice: Vec<SearchHit> = matches
            .iter()
            .skip(offset)
            .take(limit.unwrap_or(usize::MAX))
            .map(|s| SearchHit {
                seal_id: s.seal_id,
                workflow_id: s.workflow_id.clone(),
                tenant_id: s.tenant_id.clone(),
                event_type: s.event_type.clone(),
                policy_id: s.policy_id.clone(),
                sector_label: s.sector.label().to_string(),
                jurisdiction: s.jurisdiction_tag.clone(),
                timestamp: s
                    .timestamp
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            })
            .collect();
        SearchResult {
            hits: slice,
            total_matches: total,
            offset,
            limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use crate::{Hasher, Sector};
    use std::collections::BTreeMap;

    fn seal(tenant: &str, workflow: &str, event: &str, policy: &str) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: event.into(),
            event_hash: Hasher::sha256(b"e"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: policy.into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: tenant.into(),
            workflow_id: workflow.into(),
            jurisdiction_tag: "AE".into(),
            retention: RetentionClass::OneYear,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn empty_index_returns_zero() {
        let i = EvidenceSearchIndex::new();
        let r = i.search(&SearchQuery::new());
        assert_eq!(r.total_matches, 0);
    }

    #[test]
    fn search_no_filter_returns_all() {
        let i = EvidenceSearchIndex::new();
        for _ in 0..5 {
            i.add(seal("FAB", "wf", "e", "po"));
        }
        let r = i.search(&SearchQuery::new());
        assert_eq!(r.total_matches, 5);
        assert_eq!(r.hits.len(), 5);
    }

    #[test]
    fn search_by_tenant() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        i.add(seal("ENBD", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().tenant("FAB"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_by_workflow() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf-a", "e", "po"));
        i.add(seal("FAB", "wf-b", "e", "po"));
        let r = i.search(&SearchQuery::new().workflow("wf-a"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_by_event_type() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "credit", "po"));
        i.add(seal("FAB", "wf", "fx", "po"));
        let r = i.search(&SearchQuery::new().event("credit"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_by_policy() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "p1"));
        i.add(seal("FAB", "wf", "e", "p2"));
        let r = i.search(&SearchQuery::new().policy("p1"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_combines_filters() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "p1"));
        i.add(seal("FAB", "wf", "e", "p2"));
        i.add(seal("ENBD", "wf", "e", "p1"));
        let r = i.search(&SearchQuery::new().tenant("FAB").policy("p1"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_pagination() {
        let i = EvidenceSearchIndex::new();
        for _ in 0..10 {
            i.add(seal("FAB", "wf", "e", "po"));
        }
        let r = i.search(&SearchQuery::new().limit(3));
        assert_eq!(r.hits.len(), 3);
        assert_eq!(r.total_matches, 10);
    }

    #[test]
    fn search_offset() {
        let i = EvidenceSearchIndex::new();
        for _ in 0..10 {
            i.add(seal("FAB", "wf", "e", "po"));
        }
        let r = i.search(&SearchQuery::new().offset(5).limit(3));
        assert_eq!(r.hits.len(), 3);
    }

    #[test]
    fn search_by_sector_label() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().sector("Finance AI Assurance"));
        assert_eq!(r.total_matches, 1);
        // Wrong label should not match.
        let r2 = i.search(&SearchQuery::new().sector("Healthcare AI Assurance"));
        assert_eq!(r2.total_matches, 0);
    }

    #[test]
    fn search_jurisdiction_filter() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().jurisdiction("AE"));
        assert_eq!(r.total_matches, 1);
        let r2 = i.search(&SearchQuery::new().jurisdiction("EU"));
        assert_eq!(r2.total_matches, 0);
    }

    #[test]
    fn add_all_inserts_many() {
        let i = EvidenceSearchIndex::new();
        i.add_all(vec![seal("a", "w", "e", "p"), seal("b", "w", "e", "p")]);
        assert_eq!(i.len(), 2);
    }

    #[test]
    fn query_serde() {
        let q = SearchQuery::new()
            .tenant("FAB")
            .workflow("wf")
            .event("credit")
            .policy("p1")
            .limit(10)
            .offset(5);
        let j = serde_json::to_string(&q).unwrap();
        let p: SearchQuery = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn hit_serde() {
        let h = SearchHit {
            seal_id: Uuid::now_v7(),
            workflow_id: "wf".into(),
            tenant_id: "FAB".into(),
            event_type: "e".into(),
            policy_id: "p".into(),
            sector_label: "finance".into(),
            jurisdiction: "AE".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        };
        let j = serde_json::to_string(&h).unwrap();
        let p: SearchHit = serde_json::from_str(&j).unwrap();
        assert_eq!(p, h);
    }

    #[test]
    fn result_serde() {
        let r = SearchResult::default();
        let j = serde_json::to_string(&r).unwrap();
        let p: SearchResult = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn time_range_filter() {
        let i = EvidenceSearchIndex::new();
        let mut s = seal("FAB", "wf", "e", "po");
        s.timestamp = OffsetDateTime::parse(
            "2026-06-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        i.add(s);
        let r = i.search(
            &SearchQuery::new().between("2026-05-01T00:00:00Z", "2026-06-30T00:00:00Z"),
        );
        assert_eq!(r.total_matches, 1);
        let r2 = i.search(
            &SearchQuery::new().between("2027-01-01T00:00:00Z", "2027-12-31T00:00:00Z"),
        );
        assert_eq!(r2.total_matches, 0);
    }

    #[test]
    fn pagination_zero_limit_returns_no_hits_but_total() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().limit(0));
        assert_eq!(r.hits.len(), 0);
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn no_match_query() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().tenant("X"));
        assert_eq!(r.total_matches, 0);
    }

    #[test]
    fn many_seals_indexed() {
        let i = EvidenceSearchIndex::new();
        for j in 0..1000 {
            i.add(seal(&format!("t{j}"), "wf", "e", "po"));
        }
        assert_eq!(i.len(), 1000);
        let r = i.search(&SearchQuery::new().tenant("t500"));
        assert_eq!(r.total_matches, 1);
    }

    #[test]
    fn search_returns_offset_in_result() {
        let i = EvidenceSearchIndex::new();
        i.add(seal("FAB", "wf", "e", "po"));
        let r = i.search(&SearchQuery::new().offset(0));
        assert_eq!(r.offset, 0);
    }
}
