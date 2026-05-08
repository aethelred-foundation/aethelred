//! GDPR Article 17 — Right to be forgotten.
//!
//! When a data subject exercises their right to erasure under GDPR Article 17
//! (or analogous: CCPA §1798.105, UAE PDPL Art. 11, etc.), the controller
//! must erase the subject's personal data without "undue delay". This module
//! orchestrates the workflow:
//!
//! ```text
//!   ErasureRequest                                              ┌─→ Crypto-shred via [`crate::crypto_shred::ShreddingKeyVault`]
//!         │                                                     │
//!         ▼                                                     │
//!   [`ErasureLedger`] → review → approve → [`ErasureExecutor`] ─┼─→ Storage purge via [`crate::retention_purge::PurgeStorage`]
//!         │                                                     │
//!         ▼                                                     └─→ Workspace audit via [`crate::workspace_audit::WorkspaceAuditLog`]
//!   [`ErasureReceipt`]
//! ```
//!
//! ## Why this is a separate module from `crypto_shred` and `retention_purge`
//!
//! - `crypto_shred` handles the cryptographic mechanism (delete a key →
//!   ciphertext is unrecoverable).
//! - `retention_purge` handles age-based deletion.
//! - `gdpr_erasure` handles the **legal workflow**: a subject-driven request
//!   that may be approved/rejected, may be on legal hold, and produces a
//!   regulator-presentable receipt.
//!
//! ## Legal hold takes precedence
//!
//! If a subject's data is under legal hold (litigation, ongoing regulatory
//! investigation), the request is recorded as [`ErasureStatus::OnLegalHold`]
//! and not executed. GDPR Article 17(3)(e) explicitly allows preservation
//! "for the establishment, exercise or defence of legal claims."

use crate::crypto_shred::{ShreddingKeyVault, ShreddingReceipt, SubjectId};
use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ErasureRequest
// =============================================================================

/// Status of an erasure request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureStatus {
    /// Awaiting review.
    Pending,
    /// Approved — ready for execution.
    Approved,
    /// Rejected — see [`ErasureRequest::rejection_reason`].
    Rejected,
    /// Successfully executed.
    Executed,
    /// Held back due to active legal hold (GDPR 17(3)(e)).
    OnLegalHold,
    /// Request withdrawn by the subject.
    Withdrawn,
}

impl ErasureStatus {
    /// `true` if the status is terminal (no further state changes expected).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Executed | Self::Rejected | Self::Withdrawn | Self::OnLegalHold
        )
    }
}

/// One subject-initiated request to erase personal data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErasureRequest {
    /// Unique request id.
    pub request_id: Uuid,
    /// The data subject (hashed).
    pub subject: SubjectId,
    /// Tenant the subject's data lives in.
    pub tenant_id: String,
    /// RFC 3339 wall-clock when request was filed.
    pub filed_at: String,
    /// Jurisdiction citation (e.g., `"GDPR Art. 17"`, `"CCPA §1798.105"`).
    pub jurisdiction: String,
    /// Free-text reason supplied by the subject.
    pub reason: Option<String>,
    /// Identity of the operator who reviewed (if any).
    pub reviewed_by: Option<String>,
    /// Rejection reason (if [`ErasureStatus::Rejected`]).
    pub rejection_reason: Option<String>,
    /// Current status.
    pub status: ErasureStatus,
}

impl ErasureRequest {
    /// New pending request.
    pub fn new(
        subject: SubjectId,
        tenant_id: impl Into<String>,
        jurisdiction: impl Into<String>,
        reason: Option<String>,
    ) -> Self {
        let filed_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self {
            request_id: Uuid::now_v7(),
            subject,
            tenant_id: tenant_id.into(),
            filed_at,
            jurisdiction: jurisdiction.into(),
            reason,
            reviewed_by: None,
            rejection_reason: None,
            status: ErasureStatus::Pending,
        }
    }
}

// =============================================================================
// ErasureReceipt
// =============================================================================

/// Cryptographically attestable receipt produced after erasure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErasureReceipt {
    /// Receipt id.
    pub receipt_id: Uuid,
    /// Originating request id.
    pub request_id: Uuid,
    /// Subject (hashed).
    pub subject: SubjectId,
    /// Tenant.
    pub tenant_id: String,
    /// RFC 3339 timestamp.
    pub executed_at: String,
    /// Crypto-shred receipt(s) for keys destroyed.
    pub shred_receipts: Vec<ShreddingReceipt>,
    /// Number of seal records purged from storage (informational).
    pub seals_purged: u64,
    /// Hash of the receipt content (excluding `receipt_hash` itself).
    pub receipt_hash: Sha256Digest,
}

impl ErasureReceipt {
    fn compute_hash(
        request_id: &Uuid,
        subject: &SubjectId,
        tenant_id: &str,
        executed_at: &str,
        shred_receipts: &[ShreddingReceipt],
        seals_purged: u64,
    ) -> Sha256Digest {
        let mut input = Vec::new();
        input.extend_from_slice(request_id.as_bytes());
        input.extend_from_slice(&subject.as_digest().0);
        input.extend_from_slice(tenant_id.as_bytes());
        input.push(0);
        input.extend_from_slice(executed_at.as_bytes());
        input.push(0);
        input.extend_from_slice(&seals_purged.to_le_bytes());
        for r in shred_receipts {
            input.extend_from_slice(&serde_json::to_vec(r).unwrap_or_default());
        }
        Hasher::sha256(&input)
    }
}

// =============================================================================
// ErasureExecutor — pluggable erase mechanism
// =============================================================================

/// Pluggable backend that performs the actual erasure for one request.
pub trait ErasureExecutor: Send + Sync {
    /// Erase data for `subject` and return a per-subject shred receipt
    /// plus the count of storage records purged.
    fn erase(
        &self,
        subject: &SubjectId,
        tenant_id: &str,
    ) -> SandboxResult<(Vec<ShreddingReceipt>, u64)>;
}

/// In-memory test executor wired to a [`ShreddingKeyVault`].
pub struct CryptoShredExecutor {
    vault: ShreddingKeyVault,
}

impl Default for CryptoShredExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoShredExecutor {
    /// New executor with its own vault (default cipher).
    pub fn new() -> Self {
        Self {
            vault: ShreddingKeyVault::default(),
        }
    }

    /// Borrow the vault — useful in tests / setup.
    pub fn vault(&self) -> &ShreddingKeyVault {
        &self.vault
    }
}

impl ErasureExecutor for CryptoShredExecutor {
    fn erase(
        &self,
        subject: &SubjectId,
        _tenant: &str,
    ) -> SandboxResult<(Vec<ShreddingReceipt>, u64)> {
        if self.vault.is_held(subject) {
            return Err(SandboxError::Other(
                "crypto-shred refused: subject under legal hold".into(),
            ));
        }
        // If the subject is already shredded, this is idempotent — treat as
        // success with no new receipt. Avoids erroring on repeated requests.
        if self.vault.is_shredded(subject) {
            return Ok((Vec::new(), 0));
        }
        // Try to shred. The vault errors if the subject was never enrolled —
        // for an Article-17 request that is also a no-op success (the tenant
        // is effectively confirming "we never held this subject's key").
        match self.vault.shred(subject) {
            Ok(r) => Ok((vec![r], 0)),
            Err(SandboxError::Crypto(msg)) if msg.contains("not in vault") => {
                Ok((Vec::new(), 0))
            }
            Err(e) => Err(e),
        }
    }
}

// =============================================================================
// ErasureLedger
// =============================================================================

/// Append-only registry of erasure requests + their receipts.
#[derive(Default)]
pub struct ErasureLedger {
    requests: RwLock<Vec<ErasureRequest>>,
    receipts: RwLock<Vec<ErasureReceipt>>,
}

impl std::fmt::Debug for ErasureLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ErasureLedger")
            .field("requests", &self.requests.read().map(|g| g.len()).unwrap_or(0))
            .field("receipts", &self.receipts.read().map(|g| g.len()).unwrap_or(0))
            .finish()
    }
}

impl ErasureLedger {
    /// New empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// File a new erasure request.
    pub fn file(&self, req: ErasureRequest) -> SandboxResult<Uuid> {
        let id = req.request_id;
        self.requests
            .write()
            .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?
            .push(req);
        Ok(id)
    }

    /// Approve a request. Errors if not currently `Pending`.
    pub fn approve(&self, request_id: Uuid, reviewer: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .requests
            .write()
            .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
        let r = g
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        if r.status != ErasureStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot approve request in status {:?}",
                r.status
            )));
        }
        r.status = ErasureStatus::Approved;
        r.reviewed_by = Some(reviewer.into());
        Ok(())
    }

    /// Reject a request with a reason. Errors if not currently `Pending`.
    pub fn reject(
        &self,
        request_id: Uuid,
        reviewer: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .requests
            .write()
            .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
        let r = g
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        if r.status != ErasureStatus::Pending {
            return Err(SandboxError::Other(format!(
                "cannot reject request in status {:?}",
                r.status
            )));
        }
        r.status = ErasureStatus::Rejected;
        r.reviewed_by = Some(reviewer.into());
        r.rejection_reason = Some(reason.into());
        Ok(())
    }

    /// Mark a request held back due to active legal hold.
    pub fn place_on_hold(&self, request_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .requests
            .write()
            .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
        let r = g
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        if r.status.is_terminal() {
            return Err(SandboxError::Other(format!(
                "cannot place request in status {:?} on hold",
                r.status
            )));
        }
        r.status = ErasureStatus::OnLegalHold;
        Ok(())
    }

    /// Subject withdraws their request.
    pub fn withdraw(&self, request_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .requests
            .write()
            .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
        let r = g
            .iter_mut()
            .find(|r| r.request_id == request_id)
            .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
        if r.status.is_terminal() {
            return Err(SandboxError::Other(format!(
                "cannot withdraw request in status {:?}",
                r.status
            )));
        }
        r.status = ErasureStatus::Withdrawn;
        Ok(())
    }

    /// Execute an approved request via the supplied executor.
    pub fn execute(
        &self,
        request_id: Uuid,
        exec: &dyn ErasureExecutor,
    ) -> SandboxResult<ErasureReceipt> {
        // Phase 1: locate + validate state under write lock.
        let (subject, tenant) = {
            let mut g = self
                .requests
                .write()
                .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
            let r = g
                .iter_mut()
                .find(|r| r.request_id == request_id)
                .ok_or_else(|| SandboxError::Other(format!("request {} not found", request_id)))?;
            if r.status != ErasureStatus::Approved {
                return Err(SandboxError::Other(format!(
                    "cannot execute request in status {:?}",
                    r.status
                )));
            }
            (r.subject.clone(), r.tenant_id.clone())
        };

        // Phase 2: actually erase (no lock held — exec might be slow).
        let (shred_receipts, seals_purged) = exec.erase(&subject, &tenant)?;

        // Phase 3: stamp executed status + record receipt under locks.
        let executed_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let receipt_hash = ErasureReceipt::compute_hash(
            &request_id,
            &subject,
            &tenant,
            &executed_at,
            &shred_receipts,
            seals_purged,
        );
        let receipt = ErasureReceipt {
            receipt_id: Uuid::now_v7(),
            request_id,
            subject: subject.clone(),
            tenant_id: tenant.clone(),
            executed_at,
            shred_receipts,
            seals_purged,
            receipt_hash,
        };
        {
            let mut g = self
                .requests
                .write()
                .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
            if let Some(r) = g.iter_mut().find(|r| r.request_id == request_id) {
                r.status = ErasureStatus::Executed;
            }
        }
        {
            let mut g = self
                .receipts
                .write()
                .map_err(|_| SandboxError::Other("erasure ledger poisoned".into()))?;
            g.push(receipt.clone());
        }
        Ok(receipt)
    }

    /// Snapshot all requests.
    pub fn requests(&self) -> Vec<ErasureRequest> {
        self.requests.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Snapshot all receipts.
    pub fn receipts(&self) -> Vec<ErasureReceipt> {
        self.receipts.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// Number of pending requests.
    pub fn pending_count(&self) -> usize {
        self.requests
            .read()
            .map(|g| g.iter().filter(|r| r.status == ErasureStatus::Pending).count())
            .unwrap_or(0)
    }

    /// Find by request id.
    pub fn find(&self, request_id: Uuid) -> Option<ErasureRequest> {
        self.requests
            .read()
            .ok()?
            .iter()
            .find(|r| r.request_id == request_id)
            .cloned()
    }

    /// All requests for a subject.
    pub fn requests_for_subject(&self, subject: &SubjectId) -> Vec<ErasureRequest> {
        self.requests
            .read()
            .map(|g| g.iter().filter(|r| &r.subject == subject).cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subj(s: &str) -> SubjectId {
        SubjectId::hash_pii(s.as_bytes())
    }

    #[test]
    fn status_is_terminal_classifies_correctly() {
        assert!(ErasureStatus::Executed.is_terminal());
        assert!(ErasureStatus::Rejected.is_terminal());
        assert!(ErasureStatus::Withdrawn.is_terminal());
        assert!(ErasureStatus::OnLegalHold.is_terminal());
        assert!(!ErasureStatus::Pending.is_terminal());
        assert!(!ErasureStatus::Approved.is_terminal());
    }

    #[test]
    fn new_request_starts_pending() {
        let r = ErasureRequest::new(subj("alice"), "FAB", "GDPR Art. 17", Some("test".into()));
        assert_eq!(r.status, ErasureStatus::Pending);
        assert_eq!(r.tenant_id, "FAB");
        assert!(r.filed_at.contains('-'));
    }

    #[test]
    fn ledger_file_records_request() {
        let l = ErasureLedger::new();
        let r = ErasureRequest::new(subj("alice"), "FAB", "GDPR Art. 17", None);
        let id = l.file(r).unwrap();
        assert!(l.find(id).is_some());
        assert_eq!(l.pending_count(), 1);
    }

    #[test]
    fn approve_transitions_to_approved() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.approve(id, "dpo@bank").unwrap();
        let r = l.find(id).unwrap();
        assert_eq!(r.status, ErasureStatus::Approved);
        assert_eq!(r.reviewed_by.as_deref(), Some("dpo@bank"));
    }

    #[test]
    fn reject_transitions_to_rejected() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.reject(id, "dpo@bank", "ongoing investigation").unwrap();
        let r = l.find(id).unwrap();
        assert_eq!(r.status, ErasureStatus::Rejected);
        assert_eq!(r.rejection_reason.as_deref(), Some("ongoing investigation"));
    }

    #[test]
    fn approve_already_approved_errors() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.approve(id, "a").unwrap();
        assert!(l.approve(id, "b").is_err());
    }

    #[test]
    fn execute_requires_approved() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        let exec = CryptoShredExecutor::new();
        assert!(l.execute(id, &exec).is_err());
    }

    #[test]
    fn execute_runs_and_writes_receipt() {
        let l = ErasureLedger::new();
        let exec = CryptoShredExecutor::new();
        // Enroll subject so vault has something to shred.
        let s = subj("alice");
        exec.vault().encrypt(s.clone(), b"seed").unwrap();

        let id = l
            .file(ErasureRequest::new(s.clone(), "FAB", "GDPR Art. 17", None))
            .unwrap();
        l.approve(id, "dpo@bank").unwrap();
        let receipt = l.execute(id, &exec).unwrap();
        assert_eq!(receipt.request_id, id);
        assert_eq!(receipt.shred_receipts.len(), 1);
        assert!(exec.vault().is_shredded(&s));
        let r = l.find(id).unwrap();
        assert_eq!(r.status, ErasureStatus::Executed);
        assert_eq!(l.receipts().len(), 1);
    }

    #[test]
    fn execute_on_unenrolled_subject_is_idempotent_noop() {
        let l = ErasureLedger::new();
        let exec = CryptoShredExecutor::new();
        let id = l
            .file(ErasureRequest::new(
                subj("ghost"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.approve(id, "dpo").unwrap();
        let receipt = l.execute(id, &exec).unwrap();
        assert_eq!(receipt.shred_receipts.len(), 0);
        assert_eq!(receipt.seals_purged, 0);
    }

    #[test]
    fn execute_on_legal_hold_subject_errors() {
        let l = ErasureLedger::new();
        let exec = CryptoShredExecutor::new();
        let s = subj("alice");
        exec.vault().encrypt(s.clone(), b"seed").unwrap();
        exec.vault().legal_hold(&s).unwrap();
        let id = l
            .file(ErasureRequest::new(s.clone(), "FAB", "GDPR Art. 17", None))
            .unwrap();
        l.approve(id, "dpo").unwrap();
        let err = l.execute(id, &exec).expect_err("legal hold blocks");
        assert!(format!("{err}").contains("legal hold"));
    }

    #[test]
    fn place_on_hold_transitions() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.place_on_hold(id).unwrap();
        assert_eq!(l.find(id).unwrap().status, ErasureStatus::OnLegalHold);
    }

    #[test]
    fn withdraw_transitions() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.withdraw(id).unwrap();
        assert_eq!(l.find(id).unwrap().status, ErasureStatus::Withdrawn);
    }

    #[test]
    fn cannot_withdraw_terminal() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR Art. 17",
                None,
            ))
            .unwrap();
        l.reject(id, "x", "y").unwrap();
        assert!(l.withdraw(id).is_err());
    }

    #[test]
    fn requests_for_subject_filters() {
        let l = ErasureLedger::new();
        let a = subj("alice");
        let b = subj("bob");
        l.file(ErasureRequest::new(a.clone(), "FAB", "GDPR", None))
            .unwrap();
        l.file(ErasureRequest::new(b.clone(), "FAB", "GDPR", None))
            .unwrap();
        l.file(ErasureRequest::new(a.clone(), "ENBD", "CCPA", None))
            .unwrap();
        assert_eq!(l.requests_for_subject(&a).len(), 2);
        assert_eq!(l.requests_for_subject(&b).len(), 1);
    }

    #[test]
    fn pending_count_decreases_after_approval() {
        let l = ErasureLedger::new();
        let id = l
            .file(ErasureRequest::new(
                subj("alice"),
                "FAB",
                "GDPR",
                None,
            ))
            .unwrap();
        assert_eq!(l.pending_count(), 1);
        l.approve(id, "dpo").unwrap();
        assert_eq!(l.pending_count(), 0);
    }

    #[test]
    fn receipt_hash_changes_with_subject() {
        let h1 = ErasureReceipt::compute_hash(
            &Uuid::now_v7(),
            &subj("alice"),
            "FAB",
            "2026-01-01T00:00:00Z",
            &[],
            0,
        );
        let h2 = ErasureReceipt::compute_hash(
            &Uuid::now_v7(),
            &subj("bob"),
            "FAB",
            "2026-01-01T00:00:00Z",
            &[],
            0,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn request_serde_round_trip() {
        let r = ErasureRequest::new(subj("alice"), "FAB", "GDPR Art. 17", Some("x".into()));
        let j = serde_json::to_string(&r).unwrap();
        let p: ErasureRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }

    #[test]
    fn approve_unknown_request_errors() {
        let l = ErasureLedger::new();
        assert!(l.approve(Uuid::now_v7(), "x").is_err());
    }

    #[test]
    fn reject_unknown_request_errors() {
        let l = ErasureLedger::new();
        assert!(l.reject(Uuid::now_v7(), "x", "y").is_err());
    }

    #[test]
    fn execute_unknown_request_errors() {
        let l = ErasureLedger::new();
        let exec = CryptoShredExecutor::new();
        assert!(l.execute(Uuid::now_v7(), &exec).is_err());
    }

    #[test]
    fn requests_snapshot_returns_all() {
        let l = ErasureLedger::new();
        for i in 0..5 {
            l.file(ErasureRequest::new(
                subj(&format!("u{i}")),
                "FAB",
                "GDPR",
                None,
            ))
            .unwrap();
        }
        assert_eq!(l.requests().len(), 5);
    }

    #[test]
    fn double_execute_errors() {
        let l = ErasureLedger::new();
        let exec = CryptoShredExecutor::new();
        let s = subj("alice");
        exec.vault().encrypt(s.clone(), b"seed").unwrap();
        let id = l
            .file(ErasureRequest::new(s, "FAB", "GDPR", None))
            .unwrap();
        l.approve(id, "dpo").unwrap();
        l.execute(id, &exec).unwrap();
        assert!(l.execute(id, &exec).is_err());
    }

    #[test]
    fn status_serde_round_trip() {
        for s in [
            ErasureStatus::Pending,
            ErasureStatus::Approved,
            ErasureStatus::Rejected,
            ErasureStatus::Executed,
            ErasureStatus::OnLegalHold,
            ErasureStatus::Withdrawn,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: ErasureStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }
}
