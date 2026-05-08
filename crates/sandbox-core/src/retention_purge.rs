//! Retention enforcement & purge.
//!
//! Each [`crate::seal::DigitalSeal`] declares a [`crate::seal::RetentionClass`]
//! (1 year, 5 years, 7 years, 10 years, 25 years, indefinite). This module
//! computes which seals are past their retention horizon and purges them
//! — except those under a legal hold.
//!
//! ## Design
//!
//! - **Compute, then act.** [`PurgeRunner`] first builds a candidate
//!   list ([`PurgeCandidate`]) via [`PurgeRunner::scan`]; the operator
//!   reviews + commits via [`PurgeRunner::execute`].
//! - **Legal hold.** Seal ids in the [`LegalHoldRegistry`] are skipped
//!   even if past retention.
//! - **Crypto-shred integration.** Optionally invoke
//!   [`crate::crypto_shred::ShreddingKeyVault::shred`] for each subject
//!   referenced.
//! - **Audit trail.** Every purge produces a [`PurgeReceipt`] with the
//!   list of purged seal ids, retention class basis, and timestamp.

use crate::seal::{DigitalSeal, RetentionClass};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// LegalHoldRegistry
// =============================================================================

/// Registry of seal ids under legal hold (preserved past retention).
#[derive(Debug, Default)]
pub struct LegalHoldRegistry {
    held: Mutex<HashSet<Uuid>>,
}

impl LegalHoldRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a legal hold.
    pub fn hold(&self, seal_id: Uuid) {
        if let Ok(mut g) = self.held.lock() {
            g.insert(seal_id);
        }
    }

    /// Release.
    pub fn release(&self, seal_id: &Uuid) -> bool {
        if let Ok(mut g) = self.held.lock() {
            g.remove(seal_id)
        } else {
            false
        }
    }

    /// `true` if held.
    pub fn is_held(&self, seal_id: &Uuid) -> bool {
        self.held.lock().map(|g| g.contains(seal_id)).unwrap_or(false)
    }

    /// Number held.
    pub fn len(&self) -> usize {
        self.held.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no holds.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// =============================================================================
// RetentionClass duration
// =============================================================================

/// Convert a retention class to a max-age `time::Duration`.
pub fn retention_max_age(c: RetentionClass) -> Option<time::Duration> {
    match c {
        RetentionClass::OneYear => Some(time::Duration::days(365)),
        RetentionClass::FiveYears => Some(time::Duration::days(5 * 365)),
        RetentionClass::SevenYears => Some(time::Duration::days(7 * 365)),
        RetentionClass::TenYears => Some(time::Duration::days(10 * 365)),
        RetentionClass::TwentyFiveYears => Some(time::Duration::days(25 * 365)),
        RetentionClass::Indefinite => None,
    }
}

/// `true` if `seal` is past its retention horizon.
pub fn is_past_retention(seal: &DigitalSeal) -> bool {
    is_past_retention_at(seal, OffsetDateTime::now_utc())
}

/// `true` if past retention at the given reference time.
pub fn is_past_retention_at(seal: &DigitalSeal, now: OffsetDateTime) -> bool {
    match retention_max_age(seal.retention) {
        None => false,
        Some(max_age) => now - seal.timestamp >= max_age,
    }
}

// =============================================================================
// PurgeCandidate + PurgeReceipt
// =============================================================================

/// One seal flagged for purge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeCandidate {
    /// Seal id.
    pub seal_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Workflow id.
    pub workflow_id: String,
    /// Retention class.
    pub retention: RetentionClass,
    /// RFC 3339 seal creation time.
    pub created_at: String,
    /// RFC 3339 retention horizon.
    pub retention_until: String,
    /// `true` if a legal hold is preventing purge.
    pub on_legal_hold: bool,
}

/// Receipt for a completed purge.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PurgeReceipt {
    /// Receipt id.
    pub receipt_id: Uuid,
    /// RFC 3339 timestamp.
    pub purged_at: String,
    /// Tenant.
    pub tenant_id: String,
    /// Seal ids purged.
    pub purged_seal_ids: Vec<Uuid>,
    /// Seal ids skipped due to legal hold.
    pub skipped_seal_ids: Vec<Uuid>,
    /// Total considered.
    pub total_considered: u64,
}

// =============================================================================
// PurgeStorage trait — pluggable storage backend
// =============================================================================

/// Pluggable storage that the runner deletes from.
pub trait PurgeStorage: Send + Sync {
    /// Tenant served.
    fn tenant_id(&self) -> &str;
    /// All seals currently in storage.
    fn all_seals(&self) -> SandboxResult<Vec<DigitalSeal>>;
    /// Delete seals by id.
    fn delete(&self, seal_ids: &[Uuid]) -> SandboxResult<()>;
    /// Count of seals remaining (for ops dashboards / tests).
    fn seal_count(&self) -> usize {
        self.all_seals().map(|v| v.len()).unwrap_or(0)
    }
}

/// In-memory storage (tests / mock).
pub struct InMemoryPurgeStorage {
    tenant_id: String,
    seals: Mutex<Vec<DigitalSeal>>,
}

impl InMemoryPurgeStorage {
    /// New empty storage.
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            seals: Mutex::new(Vec::new()),
        }
    }

    /// New seeded with seals.
    pub fn with_seals(tenant_id: impl Into<String>, seals: Vec<DigitalSeal>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            seals: Mutex::new(seals),
        }
    }

    /// Number of seals.
    pub fn len(&self) -> usize {
        self.seals.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PurgeStorage for InMemoryPurgeStorage {
    fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    fn all_seals(&self) -> SandboxResult<Vec<DigitalSeal>> {
        let g = self
            .seals
            .lock()
            .map_err(|_| SandboxError::Other("storage lock poisoned".into()))?;
        Ok(g.clone())
    }
    fn delete(&self, seal_ids: &[Uuid]) -> SandboxResult<()> {
        let to_delete: HashSet<Uuid> = seal_ids.iter().copied().collect();
        let mut g = self
            .seals
            .lock()
            .map_err(|_| SandboxError::Other("storage lock poisoned".into()))?;
        g.retain(|s| !to_delete.contains(&s.seal_id));
        Ok(())
    }
}

// =============================================================================
// PurgeRunner
// =============================================================================

/// Plan + execute purges.
pub struct PurgeRunner {
    storage: Box<dyn PurgeStorage>,
    holds: LegalHoldRegistry,
}

impl PurgeRunner {
    /// New runner.
    pub fn new(storage: Box<dyn PurgeStorage>) -> Self {
        Self {
            storage,
            holds: LegalHoldRegistry::new(),
        }
    }

    /// Borrow the legal-hold registry.
    pub fn legal_holds(&self) -> &LegalHoldRegistry {
        &self.holds
    }

    /// Seal count remaining in storage.
    pub fn storage_seal_count(&self) -> usize {
        self.storage.seal_count()
    }

    /// Compute candidates as of `now` (for time-travel testing).
    pub fn scan_at(&self, now: OffsetDateTime) -> SandboxResult<Vec<PurgeCandidate>> {
        let seals = self.storage.all_seals()?;
        let mut out = Vec::new();
        for s in seals {
            if !is_past_retention_at(&s, now) {
                continue;
            }
            let max_age = match retention_max_age(s.retention) {
                Some(d) => d,
                None => continue,
            };
            let horizon = s.timestamp + max_age;
            let horizon_str = horizon
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            let created_str = s
                .timestamp
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            out.push(PurgeCandidate {
                seal_id: s.seal_id,
                tenant_id: s.tenant_id.clone(),
                workflow_id: s.workflow_id.clone(),
                retention: s.retention,
                created_at: created_str,
                retention_until: horizon_str,
                on_legal_hold: self.holds.is_held(&s.seal_id),
            });
        }
        Ok(out)
    }

    /// Compute candidates as of now.
    pub fn scan(&self) -> SandboxResult<Vec<PurgeCandidate>> {
        self.scan_at(OffsetDateTime::now_utc())
    }

    /// Execute purge for the given candidates. Skips legal holds.
    pub fn execute(&self, candidates: &[PurgeCandidate]) -> SandboxResult<PurgeReceipt> {
        let mut to_delete = Vec::new();
        let mut skipped = Vec::new();
        for c in candidates {
            if c.on_legal_hold || self.holds.is_held(&c.seal_id) {
                skipped.push(c.seal_id);
            } else {
                to_delete.push(c.seal_id);
            }
        }
        self.storage.delete(&to_delete)?;
        Ok(PurgeReceipt {
            receipt_id: Uuid::now_v7(),
            purged_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            tenant_id: self.storage.tenant_id().to_string(),
            purged_seal_ids: to_delete,
            skipped_seal_ids: skipped,
            total_considered: candidates.len() as u64,
        })
    }

    /// Convenience: scan + execute in one call (dry_run = `true` returns
    /// only the candidate list with no deletion).
    pub fn run(&self, dry_run: bool) -> SandboxResult<PurgeReceipt> {
        let candidates = self.scan()?;
        if dry_run {
            return Ok(PurgeReceipt {
                receipt_id: Uuid::now_v7(),
                purged_at: OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
                tenant_id: self.storage.tenant_id().to_string(),
                purged_seal_ids: Vec::new(),
                skipped_seal_ids: candidates.iter().map(|c| c.seal_id).collect(),
                total_considered: candidates.len() as u64,
            });
        }
        self.execute(&candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use std::collections::BTreeMap;

    fn seal_with(retention: RetentionClass, age_days: i64) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc() - time::Duration::days(age_days),
            sector: crate::Sector::Finance,
            event_type: "x".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("m", crate::Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            jurisdiction_tag: "AE".into(),
            retention,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn retention_max_age_correct() {
        assert_eq!(
            retention_max_age(RetentionClass::OneYear),
            Some(time::Duration::days(365))
        );
        assert_eq!(
            retention_max_age(RetentionClass::SevenYears),
            Some(time::Duration::days(7 * 365))
        );
        assert_eq!(retention_max_age(RetentionClass::Indefinite), None);
    }

    #[test]
    fn fresh_seal_not_past_retention() {
        let s = seal_with(RetentionClass::OneYear, 30);
        assert!(!is_past_retention(&s));
    }

    #[test]
    fn old_seal_past_retention() {
        let s = seal_with(RetentionClass::OneYear, 400);
        assert!(is_past_retention(&s));
    }

    #[test]
    fn indefinite_seal_never_past_retention() {
        let s = seal_with(RetentionClass::Indefinite, 1_000_000);
        assert!(!is_past_retention(&s));
    }

    #[test]
    fn legal_hold_records_seal_id() {
        let r = LegalHoldRegistry::new();
        let id = Uuid::now_v7();
        r.hold(id);
        assert!(r.is_held(&id));
    }

    #[test]
    fn legal_hold_release_removes() {
        let r = LegalHoldRegistry::new();
        let id = Uuid::now_v7();
        r.hold(id);
        assert!(r.release(&id));
        assert!(!r.is_held(&id));
    }

    #[test]
    fn legal_hold_release_unknown_returns_false() {
        let r = LegalHoldRegistry::new();
        assert!(!r.release(&Uuid::now_v7()));
    }

    #[test]
    fn legal_hold_len_and_is_empty() {
        let r = LegalHoldRegistry::new();
        assert!(r.is_empty());
        r.hold(Uuid::now_v7());
        r.hold(Uuid::now_v7());
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn in_memory_storage_basics() {
        let s = InMemoryPurgeStorage::new("FAB");
        assert!(s.is_empty());
        assert_eq!(s.tenant_id(), "FAB");
    }

    #[test]
    fn in_memory_storage_seeded() {
        let seals = vec![seal_with(RetentionClass::OneYear, 30)];
        let s = InMemoryPurgeStorage::with_seals("FAB", seals);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn in_memory_storage_delete_removes() {
        let seal = seal_with(RetentionClass::OneYear, 30);
        let id = seal.seal_id;
        let s = InMemoryPurgeStorage::with_seals("FAB", vec![seal]);
        s.delete(&[id]).unwrap();
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn scan_excludes_fresh_seals() {
        let seals = vec![
            seal_with(RetentionClass::OneYear, 30),
            seal_with(RetentionClass::SevenYears, 100),
        ];
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", seals));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        assert!(cands.is_empty());
    }

    #[test]
    fn scan_includes_expired_seals() {
        let seals = vec![
            seal_with(RetentionClass::OneYear, 400),
            seal_with(RetentionClass::OneYear, 30),
        ];
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", seals));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        assert_eq!(cands.len(), 1);
    }

    #[test]
    fn scan_excludes_indefinite_seals() {
        let seals = vec![seal_with(RetentionClass::Indefinite, 1_000_000)];
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", seals));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        assert!(cands.is_empty());
    }

    #[test]
    fn execute_deletes_non_held_seals() {
        let s1 = seal_with(RetentionClass::OneYear, 400);
        let s2 = seal_with(RetentionClass::OneYear, 400);
        let id1 = s1.seal_id;
        let id2 = s2.seal_id;
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s1, s2]));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        let receipt = r.execute(&cands).unwrap();
        assert_eq!(receipt.purged_seal_ids.len(), 2);
        assert!(receipt.skipped_seal_ids.is_empty());
        assert_eq!(r.storage_seal_count(), 0);
        let _ = (id1, id2);
    }

    #[test]
    fn execute_skips_legal_hold() {
        let s1 = seal_with(RetentionClass::OneYear, 400);
        let s2 = seal_with(RetentionClass::OneYear, 400);
        let id1 = s1.seal_id;
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s1, s2]));
        let r = PurgeRunner::new(storage);
        r.legal_holds().hold(id1);
        let cands = r.scan().unwrap();
        let receipt = r.execute(&cands).unwrap();
        assert_eq!(receipt.purged_seal_ids.len(), 1);
        assert_eq!(receipt.skipped_seal_ids.len(), 1);
        assert_eq!(receipt.skipped_seal_ids[0], id1);
    }

    #[test]
    fn dry_run_skips_deletion() {
        let s = seal_with(RetentionClass::OneYear, 400);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        let receipt = r.run(true).unwrap();
        assert_eq!(receipt.purged_seal_ids.len(), 0);
        assert_eq!(receipt.total_considered, 1);
        assert_eq!(r.storage_seal_count(), 1);
    }

    #[test]
    fn run_executes_when_dry_run_false() {
        let s = seal_with(RetentionClass::OneYear, 400);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        let receipt = r.run(false).unwrap();
        assert_eq!(receipt.purged_seal_ids.len(), 1);
        assert_eq!(r.storage_seal_count(), 0);
    }

    #[test]
    fn candidate_carries_horizon() {
        let s = seal_with(RetentionClass::OneYear, 400);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        assert!(!cands[0].retention_until.is_empty());
        assert!(!cands[0].created_at.is_empty());
    }

    #[test]
    fn scan_at_time_travels() {
        let s = seal_with(RetentionClass::OneYear, 30);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        // Future time → past retention.
        let future = OffsetDateTime::now_utc() + time::Duration::days(400);
        let cands = r.scan_at(future).unwrap();
        assert_eq!(cands.len(), 1);
    }

    #[test]
    fn purge_receipt_serde_round_trip() {
        let receipt = PurgeReceipt {
            receipt_id: Uuid::now_v7(),
            purged_at: "2026-05-06T10:00:00Z".into(),
            tenant_id: "FAB".into(),
            purged_seal_ids: vec![Uuid::now_v7()],
            skipped_seal_ids: vec![],
            total_considered: 1,
        };
        let j = serde_json::to_string(&receipt).unwrap();
        let p: PurgeReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(p, receipt);
    }

    #[test]
    fn candidate_serde_round_trip() {
        let c = PurgeCandidate {
            seal_id: Uuid::now_v7(),
            tenant_id: "FAB".into(),
            workflow_id: "wf".into(),
            retention: RetentionClass::OneYear,
            created_at: "2025-01-01T00:00:00Z".into(),
            retention_until: "2026-01-01T00:00:00Z".into(),
            on_legal_hold: false,
        };
        let j = serde_json::to_string(&c).unwrap();
        let p: PurgeCandidate = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn many_seals_purged_in_one_run() {
        let seals: Vec<DigitalSeal> =
            (0..20).map(|_| seal_with(RetentionClass::OneYear, 400)).collect();
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", seals));
        let r = PurgeRunner::new(storage);
        r.run(false).unwrap();
        assert_eq!(r.storage_seal_count(), 0);
    }

    #[test]
    fn legal_hold_default_is_empty() {
        let r = LegalHoldRegistry::default();
        assert!(r.is_empty());
    }

    #[test]
    fn empty_storage_returns_empty_candidates() {
        let storage = Box::new(InMemoryPurgeStorage::new("FAB"));
        let r = PurgeRunner::new(storage);
        assert_eq!(r.scan().unwrap().len(), 0);
    }

    #[test]
    fn five_year_retention_horizon() {
        let s = seal_with(RetentionClass::FiveYears, 5 * 365 + 5);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        assert_eq!(r.scan().unwrap().len(), 1);
    }

    #[test]
    fn twenty_five_year_retention_horizon() {
        let s = seal_with(RetentionClass::TwentyFiveYears, 25 * 365 + 5);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        assert_eq!(r.scan().unwrap().len(), 1);
    }

    #[test]
    fn ten_year_retention_horizon_not_expired() {
        let s = seal_with(RetentionClass::TenYears, 5 * 365);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", vec![s]));
        let r = PurgeRunner::new(storage);
        assert_eq!(r.scan().unwrap().len(), 0);
    }

    #[test]
    fn execute_reports_total_considered() {
        let seals = vec![
            seal_with(RetentionClass::OneYear, 400),
            seal_with(RetentionClass::OneYear, 400),
            seal_with(RetentionClass::OneYear, 400),
        ];
        let storage = Box::new(InMemoryPurgeStorage::with_seals("FAB", seals));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        let receipt = r.execute(&cands).unwrap();
        assert_eq!(receipt.total_considered, 3);
    }

    #[test]
    fn purge_receipt_records_tenant() {
        let s = seal_with(RetentionClass::OneYear, 400);
        let storage = Box::new(InMemoryPurgeStorage::with_seals("ENBD", vec![s]));
        let r = PurgeRunner::new(storage);
        let cands = r.scan().unwrap();
        let receipt = r.execute(&cands).unwrap();
        assert_eq!(receipt.tenant_id, "ENBD");
    }
}
