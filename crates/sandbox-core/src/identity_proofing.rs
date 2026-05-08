//! Identity proofing — KYC / KYB lifecycle for enterprise users.
//!
//! Records identity-verification status for principals (people, service
//! accounts, customer organizations). Each [`ProofRecord`] captures the
//! provider, level of assurance achieved, evidence references, and expiry.
//!
//! Distinct from [`crate::tenant`] which is RBAC; this module is about
//! *who you are*, not *what you can do*.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// AssuranceLevel
// =============================================================================

/// NIST SP 800-63 Identity Assurance Levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// IAL1 — self-asserted.
    Ial1,
    /// IAL2 — remote / in-person identity proofing.
    Ial2,
    /// IAL3 — in-person + biometric.
    Ial3,
}

// =============================================================================
// ProofProvider
// =============================================================================

/// Identity proofing provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofProvider {
    /// Stable id (e.g. `"jumio"`, `"persona"`, `"onfido"`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional certification reference (e.g. SOC 2 report).
    pub certification: Option<String>,
}

// =============================================================================
// ProofStatus
// =============================================================================

/// Per-record status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    /// Pending verification.
    Pending,
    /// Verified successfully.
    Verified,
    /// Failed verification.
    Failed,
    /// Expired (past `expires_at`).
    Expired,
    /// Revoked by operator.
    Revoked,
}

// =============================================================================
// SubjectKind
// =============================================================================

/// Who the proof is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// Natural person.
    Person,
    /// Legal entity / business (KYB).
    Business,
    /// Service account.
    ServiceAccount,
}

// =============================================================================
// ProofRecord
// =============================================================================

/// One identity proof record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofRecord {
    /// Stable id.
    pub record_id: Uuid,
    /// Subject id (hashed external id, principal name, etc.).
    pub subject_id: String,
    /// Subject kind.
    pub subject_kind: SubjectKind,
    /// Provider used.
    pub provider: ProofProvider,
    /// Assurance level achieved.
    pub assurance: AssuranceLevel,
    /// Status.
    pub status: ProofStatus,
    /// RFC 3339 verified at.
    pub verified_at: Option<String>,
    /// RFC 3339 expires at.
    pub expires_at: Option<String>,
    /// Optional reference id from the provider.
    pub provider_ref: Option<String>,
    /// Hash of evidence (PDF/image bundle); evidence stays out of the
    /// protocol — only its hash is recorded.
    pub evidence_hash: Sha256Digest,
}

impl ProofRecord {
    /// Computed effective status — Verified only if not expired.
    pub fn effective_status(&self, now: OffsetDateTime) -> ProofStatus {
        if matches!(self.status, ProofStatus::Revoked | ProofStatus::Failed) {
            return self.status;
        }
        if let Some(exp) = &self.expires_at {
            if let Ok(t) = OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now >= t {
                    return ProofStatus::Expired;
                }
            }
        }
        self.status
    }

    /// `true` if currently valid (Verified and not expired).
    pub fn is_currently_valid(&self, now: OffsetDateTime) -> bool {
        self.effective_status(now) == ProofStatus::Verified
    }
}

// =============================================================================
// IdentityProofRegistry
// =============================================================================

#[derive(Default)]
struct State {
    records: HashMap<Uuid, ProofRecord>,
    /// `subject_id` → list of record ids.
    by_subject: HashMap<String, Vec<Uuid>>,
}

/// Registry.
pub struct IdentityProofRegistry {
    state: RwLock<State>,
}

impl Default for IdentityProofRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for IdentityProofRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityProofRegistry")
            .field("records", &self.len())
            .finish()
    }
}

impl IdentityProofRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a record (status defaults to Pending if `verified_at` is None).
    pub fn add(
        &self,
        subject_id: impl Into<String>,
        subject_kind: SubjectKind,
        provider: ProofProvider,
        assurance: AssuranceLevel,
        evidence: &[u8],
    ) -> SandboxResult<ProofRecord> {
        let subject_id = subject_id.into();
        let r = ProofRecord {
            record_id: Uuid::now_v7(),
            subject_id: subject_id.clone(),
            subject_kind,
            provider,
            assurance,
            status: ProofStatus::Pending,
            verified_at: None,
            expires_at: None,
            provider_ref: None,
            evidence_hash: Hasher::sha256(evidence),
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("identity proof registry poisoned".into()))?;
        g.records.insert(r.record_id, r.clone());
        g.by_subject.entry(subject_id).or_default().push(r.record_id);
        Ok(r)
    }

    /// Mark as verified with optional expiry.
    pub fn mark_verified(
        &self,
        record_id: Uuid,
        provider_ref: Option<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("identity proof registry poisoned".into()))?;
        let r = g
            .records
            .get_mut(&record_id)
            .ok_or_else(|| SandboxError::Other(format!("record {} not found", record_id)))?;
        if matches!(r.status, ProofStatus::Revoked) {
            return Err(SandboxError::Other("record is revoked".into()));
        }
        r.status = ProofStatus::Verified;
        r.verified_at = Some(
            OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        );
        r.expires_at = expires_at.map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        });
        r.provider_ref = provider_ref;
        Ok(())
    }

    /// Mark as failed.
    pub fn mark_failed(&self, record_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("identity proof registry poisoned".into()))?;
        let r = g
            .records
            .get_mut(&record_id)
            .ok_or_else(|| SandboxError::Other(format!("record {} not found", record_id)))?;
        r.status = ProofStatus::Failed;
        Ok(())
    }

    /// Revoke.
    pub fn revoke(&self, record_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("identity proof registry poisoned".into()))?;
        let r = g
            .records
            .get_mut(&record_id)
            .ok_or_else(|| SandboxError::Other(format!("record {} not found", record_id)))?;
        r.status = ProofStatus::Revoked;
        Ok(())
    }

    /// Lookup by id.
    pub fn get(&self, record_id: Uuid) -> Option<ProofRecord> {
        self.state.read().ok()?.records.get(&record_id).cloned()
    }

    /// Records for a subject.
    pub fn for_subject(&self, subject_id: &str) -> Vec<ProofRecord> {
        let g = match self.state.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let ids = match g.by_subject.get(subject_id) {
            Some(v) => v.clone(),
            None => return Vec::new(),
        };
        ids.into_iter()
            .filter_map(|id| g.records.get(&id).cloned())
            .collect()
    }

    /// Latest valid record for a subject as of `now` with `>= min_assurance`.
    pub fn latest_valid(
        &self,
        subject_id: &str,
        min_assurance: AssuranceLevel,
        now: OffsetDateTime,
    ) -> Option<ProofRecord> {
        self.for_subject(subject_id)
            .into_iter()
            .filter(|r| r.is_currently_valid(now))
            .filter(|r| r.assurance >= min_assurance)
            .max_by(|a, b| {
                a.verified_at.cmp(&b.verified_at)
            })
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.records.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> ProofProvider {
        ProofProvider {
            id: "jumio".into(),
            name: "Jumio".into(),
            certification: Some("SOC 2 Type II".into()),
        }
    }

    #[test]
    fn add_creates_record() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"evidence",
            )
            .unwrap();
        assert_eq!(rec.status, ProofStatus::Pending);
        assert_eq!(rec.assurance, AssuranceLevel::Ial2);
    }

    #[test]
    fn mark_verified_sets_status() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        r.mark_verified(rec.record_id, Some("pref-1".into()), None)
            .unwrap();
        let r2 = r.get(rec.record_id).unwrap();
        assert_eq!(r2.status, ProofStatus::Verified);
        assert!(r2.verified_at.is_some());
    }

    #[test]
    fn mark_verified_unknown_errors() {
        let r = IdentityProofRegistry::new();
        assert!(r.mark_verified(Uuid::now_v7(), None, None).is_err());
    }

    #[test]
    fn revoked_blocks_verify() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        r.revoke(rec.record_id).unwrap();
        assert!(r.mark_verified(rec.record_id, None, None).is_err());
    }

    #[test]
    fn effective_status_handles_expiry() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        let past_exp = OffsetDateTime::now_utc() - time::Duration::days(1);
        r.mark_verified(rec.record_id, None, Some(past_exp)).unwrap();
        let r2 = r.get(rec.record_id).unwrap();
        assert_eq!(
            r2.effective_status(OffsetDateTime::now_utc()),
            ProofStatus::Expired
        );
    }

    #[test]
    fn is_currently_valid_strict() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        let future_exp = OffsetDateTime::now_utc() + time::Duration::days(365);
        r.mark_verified(rec.record_id, None, Some(future_exp))
            .unwrap();
        let r2 = r.get(rec.record_id).unwrap();
        assert!(r2.is_currently_valid(OffsetDateTime::now_utc()));
    }

    #[test]
    fn for_subject_returns_records() {
        let r = IdentityProofRegistry::new();
        r.add(
            "alice",
            SubjectKind::Person,
            provider(),
            AssuranceLevel::Ial2,
            b"e1",
        )
        .unwrap();
        r.add(
            "alice",
            SubjectKind::Person,
            provider(),
            AssuranceLevel::Ial3,
            b"e2",
        )
        .unwrap();
        let v = r.for_subject("alice");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn latest_valid_picks_highest_assurance() {
        let r = IdentityProofRegistry::new();
        let r1 = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e1",
            )
            .unwrap();
        r.mark_verified(r1.record_id, None, None).unwrap();
        let v = r
            .latest_valid("alice", AssuranceLevel::Ial2, OffsetDateTime::now_utc())
            .unwrap();
        assert_eq!(v.assurance, AssuranceLevel::Ial2);
    }

    #[test]
    fn latest_valid_filters_by_min_assurance() {
        let r = IdentityProofRegistry::new();
        let r1 = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial1,
                b"e",
            )
            .unwrap();
        r.mark_verified(r1.record_id, None, None).unwrap();
        let v = r.latest_valid("alice", AssuranceLevel::Ial3, OffsetDateTime::now_utc());
        assert!(v.is_none());
    }

    #[test]
    fn mark_failed_sets_status() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        r.mark_failed(rec.record_id).unwrap();
        assert_eq!(r.get(rec.record_id).unwrap().status, ProofStatus::Failed);
    }

    #[test]
    fn assurance_level_ordering() {
        assert!(AssuranceLevel::Ial3 > AssuranceLevel::Ial2);
        assert!(AssuranceLevel::Ial2 > AssuranceLevel::Ial1);
    }

    #[test]
    fn assurance_serde() {
        for a in [
            AssuranceLevel::Ial1,
            AssuranceLevel::Ial2,
            AssuranceLevel::Ial3,
        ] {
            let j = serde_json::to_string(&a).unwrap();
            let p: AssuranceLevel = serde_json::from_str(&j).unwrap();
            assert_eq!(a, p);
        }
    }

    #[test]
    fn status_serde() {
        for s in [
            ProofStatus::Pending,
            ProofStatus::Verified,
            ProofStatus::Failed,
            ProofStatus::Expired,
            ProofStatus::Revoked,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ProofStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(s, p);
        }
    }

    #[test]
    fn subject_kind_serde() {
        for k in [
            SubjectKind::Person,
            SubjectKind::Business,
            SubjectKind::ServiceAccount,
        ] {
            let j = serde_json::to_string(&k).unwrap();
            let p: SubjectKind = serde_json::from_str(&j).unwrap();
            assert_eq!(k, p);
        }
    }

    #[test]
    fn record_serde() {
        let r = IdentityProofRegistry::new();
        let rec = r
            .add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        let j = serde_json::to_string(&rec).unwrap();
        let p: ProofRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(p, rec);
    }

    #[test]
    fn provider_serde() {
        let p = provider();
        let j = serde_json::to_string(&p).unwrap();
        let q: ProofProvider = serde_json::from_str(&j).unwrap();
        assert_eq!(p, q);
    }

    #[test]
    fn evidence_hash_deterministic() {
        let r = IdentityProofRegistry::new();
        let r1 = r
            .add(
                "a",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"x",
            )
            .unwrap();
        let r2 = r
            .add(
                "b",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"x",
            )
            .unwrap();
        assert_eq!(r1.evidence_hash, r2.evidence_hash);
    }

    #[test]
    fn lookup_unknown_returns_none() {
        let r = IdentityProofRegistry::new();
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn registry_empty() {
        let r = IdentityProofRegistry::new();
        assert!(r.is_empty());
    }

    #[test]
    fn revoke_unknown_errors() {
        let r = IdentityProofRegistry::new();
        assert!(r.revoke(Uuid::now_v7()).is_err());
    }

    #[test]
    fn mark_failed_unknown_errors() {
        let r = IdentityProofRegistry::new();
        assert!(r.mark_failed(Uuid::now_v7()).is_err());
    }

    #[test]
    fn many_records_per_subject() {
        let r = IdentityProofRegistry::new();
        for _ in 0..10 {
            r.add(
                "alice",
                SubjectKind::Person,
                provider(),
                AssuranceLevel::Ial2,
                b"e",
            )
            .unwrap();
        }
        assert_eq!(r.for_subject("alice").len(), 10);
    }
}
