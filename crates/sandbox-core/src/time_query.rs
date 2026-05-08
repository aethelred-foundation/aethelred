//! Time-window queries over the evidence log.
//!
//! Auditors and SOC analysts ask:
//!
//! - "Show me every credit decision sealed for FAB between 2026-05-06T08:00Z
//!    and 2026-05-06T18:00Z."
//! - "How many denials for `agent-007` in the last hour?"
//! - "Filter to a specific sector + jurisdiction + signed-by-validator-1."
//!
//! [`TimeQuery`] is a fluent builder over an [`crate::EvidenceLog`] (or any
//! `Vec<EvidenceLogEntry>`) that returns matching entries in O(N) — fine
//! for log sizes up to a few million; production deployments add
//! per-day index files on top.

use crate::evidence::{EvidenceBundle, EvidenceLogEntry};
use crate::seal::DigitalSeal;
use crate::Sector;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Filter predicate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeQuery {
    /// Earliest timestamp (inclusive). RFC 3339.
    pub from: Option<String>,
    /// Latest timestamp (exclusive). RFC 3339.
    pub to: Option<String>,
    /// Tenant filter (exact match).
    pub tenant_id: Option<String>,
    /// Sector filter.
    pub sector: Option<Sector>,
    /// Workflow id filter (exact match).
    pub workflow_id: Option<String>,
    /// Event type filter (substring match).
    pub event_type_contains: Option<String>,
    /// Jurisdiction tag filter (exact match).
    pub jurisdiction_tag: Option<String>,
    /// Only entries that have a validator signature.
    pub signed_only: bool,
    /// Only entries that have an attestation.
    pub attested_only: bool,
    /// Only entries that have a zkML proof.
    pub zk_proof_only: bool,
    /// Maximum results to return. `None` = unlimited.
    pub limit: Option<usize>,
}

impl TimeQuery {
    /// Empty query (matches everything).
    pub fn new() -> Self {
        Self::default()
    }

    /// Set lower bound.
    pub fn from(mut self, t: impl Into<String>) -> Self {
        self.from = Some(t.into());
        self
    }
    /// Set upper bound.
    pub fn to(mut self, t: impl Into<String>) -> Self {
        self.to = Some(t.into());
        self
    }
    /// Filter by tenant.
    pub fn tenant(mut self, t: impl Into<String>) -> Self {
        self.tenant_id = Some(t.into());
        self
    }
    /// Filter by sector.
    pub fn sector(mut self, s: Sector) -> Self {
        self.sector = Some(s);
        self
    }
    /// Filter by workflow id.
    pub fn workflow(mut self, w: impl Into<String>) -> Self {
        self.workflow_id = Some(w.into());
        self
    }
    /// Filter by event type substring.
    pub fn event_type_contains(mut self, s: impl Into<String>) -> Self {
        self.event_type_contains = Some(s.into());
        self
    }
    /// Filter by jurisdiction.
    pub fn jurisdiction(mut self, j: impl Into<String>) -> Self {
        self.jurisdiction_tag = Some(j.into());
        self
    }
    /// Only signed seals.
    pub fn signed_only(mut self) -> Self {
        self.signed_only = true;
        self
    }
    /// Only attested seals.
    pub fn attested_only(mut self) -> Self {
        self.attested_only = true;
        self
    }
    /// Only seals with zkML proofs.
    pub fn zk_proof_only(mut self) -> Self {
        self.zk_proof_only = true;
        self
    }
    /// Cap returned results.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Test `seal` against the filter.
    pub fn matches(&self, seal: &DigitalSeal) -> SandboxResult<bool> {
        if let Some(from) = &self.from {
            let lo = OffsetDateTime::parse(from, &Rfc3339)
                .map_err(|e| SandboxError::invalid(format!("from rfc3339: {e}")))?;
            if seal.timestamp < lo {
                return Ok(false);
            }
        }
        if let Some(to) = &self.to {
            let hi = OffsetDateTime::parse(to, &Rfc3339)
                .map_err(|e| SandboxError::invalid(format!("to rfc3339: {e}")))?;
            if seal.timestamp >= hi {
                return Ok(false);
            }
        }
        if let Some(t) = &self.tenant_id {
            if &seal.tenant_id != t {
                return Ok(false);
            }
        }
        if let Some(s) = &self.sector {
            if &seal.sector != s {
                return Ok(false);
            }
        }
        if let Some(w) = &self.workflow_id {
            if &seal.workflow_id != w {
                return Ok(false);
            }
        }
        if let Some(et) = &self.event_type_contains {
            if !seal.event_type.contains(et.as_str()) {
                return Ok(false);
            }
        }
        if let Some(j) = &self.jurisdiction_tag {
            if &seal.jurisdiction_tag != j {
                return Ok(false);
            }
        }
        if self.signed_only && seal.validator_signature_hex.is_none() {
            return Ok(false);
        }
        if self.attested_only && seal.attestation.is_none() {
            return Ok(false);
        }
        if self.zk_proof_only && seal.zk_proof.is_none() {
            return Ok(false);
        }
        Ok(true)
    }

    /// Run the query against a slice of entries.
    pub fn run(&self, entries: &[EvidenceLogEntry]) -> SandboxResult<Vec<EvidenceLogEntry>> {
        let mut out = Vec::new();
        for e in entries {
            if self.matches(&e.seal)? {
                out.push(e.clone());
                if let Some(limit) = self.limit {
                    if out.len() >= limit {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    /// Run the query against a bundle's entries.
    pub fn run_bundle(&self, bundle: &EvidenceBundle) -> SandboxResult<Vec<EvidenceLogEntry>> {
        self.run(&bundle.entries)
    }

    /// Count matches without materialising them.
    pub fn count(&self, entries: &[EvidenceLogEntry]) -> SandboxResult<u64> {
        let mut n: u64 = 0;
        for e in entries {
            if self.matches(&e.seal)? {
                n += 1;
            }
        }
        Ok(n)
    }
}

/// Bucket counts by minute-of-day, hour-of-day, or RFC 3339 day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// Group by hour-of-day (0..24), tagged as `"HH:00"`.
    Hour,
    /// Group by RFC 3339 day prefix (`"YYYY-MM-DD"`).
    Day,
    /// Group by week (ISO week-numbering).
    Week,
}

/// Time-bucketed histogram of seal counts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeHistogram {
    /// `bucket_label → count`.
    pub counts: std::collections::BTreeMap<String, u64>,
}

impl TimeHistogram {
    /// Total count across buckets.
    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }
}

/// Bucketise the matches of a query.
pub fn histogram(
    query: &TimeQuery,
    entries: &[EvidenceLogEntry],
    bucket: Bucket,
) -> SandboxResult<TimeHistogram> {
    let mut h = TimeHistogram::default();
    for e in entries {
        if query.matches(&e.seal)? {
            let label = bucket_label(e.seal.timestamp, bucket);
            *h.counts.entry(label).or_insert(0) += 1;
        }
    }
    Ok(h)
}

fn bucket_label(t: OffsetDateTime, bucket: Bucket) -> String {
    match bucket {
        Bucket::Hour => format!("{:02}:00", t.hour()),
        Bucket::Day => {
            let date = t.date();
            format!(
                "{:04}-{:02}-{:02}",
                date.year(),
                date.month() as u8,
                date.day()
            )
        }
        Bucket::Week => {
            let iso = t.to_iso_week_date();
            format!("{:04}-W{:02}", iso.0, iso.1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceLog;
    use crate::hashing::Hasher;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn seal(
        tenant: &str,
        sector: Sector,
        workflow: &str,
        event: &str,
        when: OffsetDateTime,
    ) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: when,
            sector,
            event_type: event.into(),
            event_hash: Hasher::sha256(b"e"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: tenant.into(),
            workflow_id: workflow.into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn entries(seals: Vec<DigitalSeal>) -> Vec<EvidenceLogEntry> {
        let log = EvidenceLog::new();
        for s in seals {
            log.append(s).unwrap();
        }
        let bundle = log.export("FAB", Sector::Finance).unwrap();
        bundle.entries
    }

    #[test]
    fn empty_query_matches_all() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "credit_decision", "credit_decision.approved", now),
            seal("ENBD", Sector::Finance, "aml_screening", "aml_screening.cleared", now),
        ]);
        let q = TimeQuery::new();
        assert_eq!(q.run(&es).unwrap().len(), 2);
    }

    #[test]
    fn from_to_filters_by_time() {
        let t1 = OffsetDateTime::now_utc();
        let t2 = t1 + time::Duration::hours(2);
        let t3 = t1 + time::Duration::hours(4);
        let es = entries(vec![
            seal("FAB", Sector::Finance, "credit_decision", "credit", t1),
            seal("FAB", Sector::Finance, "credit_decision", "credit", t2),
            seal("FAB", Sector::Finance, "credit_decision", "credit", t3),
        ]);
        let from = (t1 + time::Duration::hours(1))
            .format(&Rfc3339)
            .unwrap();
        let to = (t1 + time::Duration::hours(3)).format(&Rfc3339).unwrap();
        let q = TimeQuery::new().from(from).to(to);
        let r = q.run(&es).unwrap();
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn tenant_filter() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", now),
            seal("ENBD", Sector::Finance, "x", "x", now),
            seal("FAB", Sector::Finance, "x", "x", now),
        ]);
        let q = TimeQuery::new().tenant("FAB");
        assert_eq!(q.run(&es).unwrap().len(), 2);
    }

    #[test]
    fn sector_filter() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", now),
            seal("FAB", Sector::Healthcare, "x", "x", now),
            seal("FAB", Sector::Finance, "x", "x", now),
        ]);
        let q = TimeQuery::new().sector(Sector::Finance);
        assert_eq!(q.run(&es).unwrap().len(), 2);
    }

    #[test]
    fn workflow_filter() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "credit_decision", "x", now),
            seal("FAB", Sector::Finance, "aml_screening", "x", now),
        ]);
        let q = TimeQuery::new().workflow("credit_decision");
        assert_eq!(q.run(&es).unwrap().len(), 1);
    }

    #[test]
    fn event_type_substring_filter() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "credit_decision.approved", now),
            seal("FAB", Sector::Finance, "x", "credit_decision.declined", now),
            seal("FAB", Sector::Finance, "x", "aml_screening.cleared", now),
        ]);
        let q = TimeQuery::new().event_type_contains("credit_decision");
        assert_eq!(q.run(&es).unwrap().len(), 2);
    }

    #[test]
    fn jurisdiction_filter() {
        let now = OffsetDateTime::now_utc();
        let mut s1 = seal("FAB", Sector::Finance, "x", "x", now);
        s1.jurisdiction_tag = "AE-CBUAE".into();
        let mut s2 = seal("FAB", Sector::Finance, "x", "x", now);
        s2.jurisdiction_tag = "UK-FCA".into();
        let es = entries(vec![s1, s2]);
        let q = TimeQuery::new().jurisdiction("UK-FCA");
        assert_eq!(q.run(&es).unwrap().len(), 1);
    }

    #[test]
    fn signed_only_filter() {
        let now = OffsetDateTime::now_utc();
        let mut s1 = seal("FAB", Sector::Finance, "x", "x", now);
        s1.validator_signature_hex = Some("deadbeef".into());
        let s2 = seal("FAB", Sector::Finance, "x", "x", now);
        let es = entries(vec![s1, s2]);
        let q = TimeQuery::new().signed_only();
        assert_eq!(q.run(&es).unwrap().len(), 1);
    }

    #[test]
    fn limit_caps_output() {
        let now = OffsetDateTime::now_utc();
        let es = entries((0..20).map(|_| seal("FAB", Sector::Finance, "x", "x", now)).collect());
        let q = TimeQuery::new().limit(5);
        assert_eq!(q.run(&es).unwrap().len(), 5);
    }

    #[test]
    fn count_matches_run_len() {
        let now = OffsetDateTime::now_utc();
        let es = entries((0..10).map(|_| seal("FAB", Sector::Finance, "x", "x", now)).collect());
        let q = TimeQuery::new().tenant("FAB");
        let n = q.count(&es).unwrap();
        let m = q.run(&es).unwrap().len();
        assert_eq!(n, m as u64);
    }

    #[test]
    fn bad_from_format_errors() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![seal("FAB", Sector::Finance, "x", "x", now)]);
        let q = TimeQuery::new().from("not-a-date");
        assert!(q.run(&es).is_err());
    }

    #[test]
    fn bad_to_format_errors() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![seal("FAB", Sector::Finance, "x", "x", now)]);
        let q = TimeQuery::new().to("not-a-date");
        assert!(q.run(&es).is_err());
    }

    #[test]
    fn run_bundle_works() {
        let now = OffsetDateTime::now_utc();
        let log = EvidenceLog::new();
        for _ in 0..3 {
            log.append(seal("FAB", Sector::Finance, "x", "x", now)).unwrap();
        }
        let bundle = log.export("FAB", Sector::Finance).unwrap();
        let q = TimeQuery::new().tenant("FAB");
        assert_eq!(q.run_bundle(&bundle).unwrap().len(), 3);
    }

    #[test]
    fn histogram_buckets_by_hour() {
        let base = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", base),
            seal("FAB", Sector::Finance, "x", "x", base),
            seal("FAB", Sector::Finance, "x", "x", base + time::Duration::hours(1)),
        ]);
        let q = TimeQuery::new();
        let h = histogram(&q, &es, Bucket::Hour).unwrap();
        assert_eq!(h.total(), 3);
        assert_eq!(h.counts.len(), 2);
    }

    #[test]
    fn histogram_buckets_by_day() {
        let base = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", base),
            seal("FAB", Sector::Finance, "x", "x", base + time::Duration::days(1)),
            seal("FAB", Sector::Finance, "x", "x", base + time::Duration::days(1) + time::Duration::hours(2)),
        ]);
        let q = TimeQuery::new();
        let h = histogram(&q, &es, Bucket::Day).unwrap();
        assert_eq!(h.counts.len(), 2);
        assert_eq!(h.total(), 3);
    }

    #[test]
    fn histogram_respects_filter() {
        let base = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", base),
            seal("ENBD", Sector::Finance, "x", "x", base),
            seal("FAB", Sector::Finance, "x", "x", base),
        ]);
        let q = TimeQuery::new().tenant("FAB");
        let h = histogram(&q, &es, Bucket::Day).unwrap();
        assert_eq!(h.total(), 2);
    }

    #[test]
    fn histogram_buckets_by_week() {
        let base = OffsetDateTime::from_unix_timestamp(1_780_000_000).unwrap();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "x", "x", base),
            seal("FAB", Sector::Finance, "x", "x", base + time::Duration::days(8)),
        ]);
        let q = TimeQuery::new();
        let h = histogram(&q, &es, Bucket::Week).unwrap();
        assert_eq!(h.counts.len(), 2);
    }

    #[test]
    fn empty_input_returns_empty_results() {
        let q = TimeQuery::new();
        assert_eq!(q.run(&[]).unwrap().len(), 0);
        assert_eq!(q.count(&[]).unwrap(), 0);
    }

    #[test]
    fn combined_filters() {
        let now = OffsetDateTime::now_utc();
        let es = entries(vec![
            seal("FAB", Sector::Finance, "credit_decision", "x", now),
            seal("FAB", Sector::Healthcare, "clinical_ai", "x", now),
            seal("ENBD", Sector::Finance, "credit_decision", "x", now),
        ]);
        let q = TimeQuery::new()
            .tenant("FAB")
            .sector(Sector::Finance)
            .workflow("credit_decision");
        assert_eq!(q.run(&es).unwrap().len(), 1);
    }

    #[test]
    fn query_serde_round_trip() {
        let q = TimeQuery::new()
            .tenant("FAB")
            .sector(Sector::Finance)
            .workflow("credit_decision")
            .signed_only()
            .limit(100);
        let j = serde_json::to_string(&q).unwrap();
        let p: TimeQuery = serde_json::from_str(&j).unwrap();
        assert_eq!(p.tenant_id, q.tenant_id);
        assert_eq!(p.sector, q.sector);
        assert_eq!(p.signed_only, q.signed_only);
        assert_eq!(p.limit, q.limit);
    }
}
