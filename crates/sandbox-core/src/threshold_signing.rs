//! M-of-N threshold signature collection.
//!
//! Many regulatory operations (large transactions, key rotations, model
//! promotions) require multiple authorized signers. This module models
//! threshold-style signing **at the application layer**: the actual
//! cryptographic signatures live in [`crate::crypto_signing`]; this module
//! tracks who signed, when, and emits an [`AssembledSignature`] once the
//! threshold is met.
//!
//! It is *not* a real BLS / Schnorr threshold — it's an "M-of-N quorum
//! collector" with HMAC-style verification of share commitment per signer.
//! Production deployments swap the verification primitive for a real
//! threshold scheme.

use crate::hashing::{Hasher, Sha256Digest};
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// SigningCeremony
// =============================================================================

/// One ceremony.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigningCeremony {
    /// Stable id.
    pub ceremony_id: Uuid,
    /// Subject hash being signed (the message digest).
    pub subject_hash: Sha256Digest,
    /// Required threshold.
    pub threshold_m: u32,
    /// Total enrolled signers.
    pub total_n: u32,
    /// Set of authorized signer ids.
    pub authorized_signers: Vec<String>,
    /// RFC 3339 created at.
    pub created_at: String,
    /// RFC 3339 expires at (optional).
    pub expires_at: Option<String>,
    /// Free-text purpose.
    pub purpose: String,
    /// Status.
    pub status: CeremonyStatus,
}

/// Lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStatus {
    /// Open for signing.
    Open,
    /// Threshold met → signature can be assembled.
    ThresholdReached,
    /// Successfully assembled.
    Finalized,
    /// Aborted.
    Aborted,
    /// Expired.
    Expired,
}

// =============================================================================
// Share + AssembledSignature
// =============================================================================

/// One signer's share.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureShare {
    /// Signer id.
    pub signer_id: String,
    /// Hash of the share contents (`subject_hash || signer_id || nonce`)
    /// — represents the share's commitment.
    pub commitment: Sha256Digest,
    /// Optional signer nonce (hex).
    pub nonce_hex: String,
    /// RFC 3339 timestamp.
    pub at: String,
}

/// Final assembled signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssembledSignature {
    /// Ceremony id.
    pub ceremony_id: Uuid,
    /// Subject hash.
    pub subject_hash: Sha256Digest,
    /// Aggregate hash of all included shares (deterministic given the same
    /// ordered share list).
    pub aggregate_hash: Sha256Digest,
    /// Number of shares (= threshold_m at finalization time).
    pub share_count: u32,
    /// Signer ids included.
    pub signer_ids: Vec<String>,
    /// RFC 3339 finalized at.
    pub finalized_at: String,
}

// =============================================================================
// CeremonyRegistry
// =============================================================================

#[derive(Default)]
struct State {
    ceremonies: HashMap<Uuid, SigningCeremony>,
    /// `ceremony_id` → shares.
    shares: HashMap<Uuid, Vec<SignatureShare>>,
    /// `ceremony_id` → final.
    finalized: HashMap<Uuid, AssembledSignature>,
}

/// Registry.
pub struct CeremonyRegistry {
    state: RwLock<State>,
}

impl Default for CeremonyRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(State::default()),
        }
    }
}

impl std::fmt::Debug for CeremonyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CeremonyRegistry")
            .field("ceremonies", &self.len())
            .finish()
    }
}

impl CeremonyRegistry {
    /// New empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new ceremony. Errors if `m > n` or `m == 0`.
    pub fn open(
        &self,
        subject_hash: Sha256Digest,
        threshold_m: u32,
        authorized: Vec<String>,
        purpose: impl Into<String>,
        expires_at: Option<OffsetDateTime>,
    ) -> SandboxResult<SigningCeremony> {
        let total_n = authorized.len() as u32;
        if threshold_m == 0 {
            return Err(SandboxError::Other("threshold must be > 0".into()));
        }
        if threshold_m > total_n {
            return Err(SandboxError::Other(format!(
                "threshold {} > total signers {}",
                threshold_m, total_n
            )));
        }
        // Dedup authorized signer ids.
        let mut seen: HashSet<String> = HashSet::new();
        for s in &authorized {
            if !seen.insert(s.clone()) {
                return Err(SandboxError::Other(format!(
                    "duplicate signer {} in authorized list",
                    s
                )));
            }
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let exp = expires_at
            .map(|t| t.format(&time::format_description::well_known::Rfc3339).unwrap_or_default());
        let c = SigningCeremony {
            ceremony_id: Uuid::now_v7(),
            subject_hash,
            threshold_m,
            total_n,
            authorized_signers: authorized,
            created_at: now,
            expires_at: exp,
            purpose: purpose.into(),
            status: CeremonyStatus::Open,
        };
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("ceremony registry poisoned".into()))?;
        g.ceremonies.insert(c.ceremony_id, c.clone());
        g.shares.insert(c.ceremony_id, Vec::new());
        Ok(c)
    }

    /// Submit a share. Errors if signer not authorized, ceremony not open,
    /// signer already submitted, or expired.
    pub fn submit_share(
        &self,
        ceremony_id: Uuid,
        signer_id: impl Into<String>,
        nonce_hex: impl Into<String>,
        now: OffsetDateTime,
    ) -> SandboxResult<SignatureShare> {
        let signer_id = signer_id.into();
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("ceremony registry poisoned".into()))?;
        let ceremony = g
            .ceremonies
            .get_mut(&ceremony_id)
            .ok_or_else(|| SandboxError::Other(format!("ceremony {} not found", ceremony_id)))?;

        // Lifecycle.
        if ceremony.status == CeremonyStatus::Finalized
            || ceremony.status == CeremonyStatus::Aborted
        {
            return Err(SandboxError::Other(format!(
                "ceremony {} is in terminal state {:?}",
                ceremony_id, ceremony.status
            )));
        }
        // Expiry.
        if let Some(exp) = &ceremony.expires_at {
            if let Ok(t) = OffsetDateTime::parse(
                exp,
                &time::format_description::well_known::Rfc3339,
            ) {
                if now > t {
                    ceremony.status = CeremonyStatus::Expired;
                    return Err(SandboxError::Other(format!(
                        "ceremony {} expired",
                        ceremony_id
                    )));
                }
            }
        }
        // Authorization.
        if !ceremony.authorized_signers.iter().any(|s| s == &signer_id) {
            return Err(SandboxError::Other(format!(
                "signer {} not authorized",
                signer_id
            )));
        }
        // Snapshot subject_hash from ceremony for commitment.
        let subject = ceremony.subject_hash.clone();
        let threshold_m = ceremony.threshold_m;
        // Dedup.
        let shares = g.shares.entry(ceremony_id).or_default();
        if shares.iter().any(|s| s.signer_id == signer_id) {
            return Err(SandboxError::Other(format!(
                "signer {} already submitted",
                signer_id
            )));
        }
        let nonce_hex = nonce_hex.into();
        let mut input = Vec::new();
        input.extend_from_slice(&subject.0);
        input.extend_from_slice(signer_id.as_bytes());
        input.extend_from_slice(nonce_hex.as_bytes());
        let commitment = Hasher::sha256(&input);
        let share = SignatureShare {
            signer_id: signer_id.clone(),
            commitment,
            nonce_hex,
            at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        shares.push(share.clone());
        let count = shares.len() as u32;
        // Update status if threshold reached.
        if let Some(c) = g.ceremonies.get_mut(&ceremony_id) {
            if count >= threshold_m && c.status == CeremonyStatus::Open {
                c.status = CeremonyStatus::ThresholdReached;
            }
        }
        Ok(share)
    }

    /// Finalize: produce the assembled signature once threshold is met.
    pub fn finalize(&self, ceremony_id: Uuid) -> SandboxResult<AssembledSignature> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("ceremony registry poisoned".into()))?;
        // Snapshot ceremony fields immutably first.
        let (status, threshold_m, subject_hash) = {
            let c = g.ceremonies.get(&ceremony_id).ok_or_else(|| {
                SandboxError::Other(format!("ceremony {} not found", ceremony_id))
            })?;
            (c.status, c.threshold_m, c.subject_hash.clone())
        };
        if status == CeremonyStatus::Finalized {
            return g
                .finalized
                .get(&ceremony_id)
                .cloned()
                .ok_or_else(|| SandboxError::Other("ceremony already finalized but missing".into()));
        }
        if status == CeremonyStatus::Aborted || status == CeremonyStatus::Expired {
            return Err(SandboxError::Other(format!(
                "cannot finalize ceremony in state {:?}",
                status
            )));
        }
        let shares = g.shares.get(&ceremony_id).cloned().unwrap_or_default();
        if (shares.len() as u32) < threshold_m {
            return Err(SandboxError::Other(format!(
                "threshold {} not yet met (have {})",
                threshold_m,
                shares.len()
            )));
        }
        // Take exactly `threshold_m` shares (in submission order) for determinism.
        let used = &shares[..threshold_m as usize];
        let mut input = Vec::new();
        input.extend_from_slice(&subject_hash.0);
        for s in used {
            input.extend_from_slice(s.signer_id.as_bytes());
            input.push(0);
            input.extend_from_slice(&s.commitment.0);
        }
        let aggregate = Hasher::sha256(&input);
        let signer_ids: Vec<String> = used.iter().map(|s| s.signer_id.clone()).collect();
        let assembled = AssembledSignature {
            ceremony_id,
            subject_hash,
            aggregate_hash: aggregate,
            share_count: threshold_m,
            signer_ids,
            finalized_at: OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        };
        if let Some(c) = g.ceremonies.get_mut(&ceremony_id) {
            c.status = CeremonyStatus::Finalized;
        }
        g.finalized.insert(ceremony_id, assembled.clone());
        Ok(assembled)
    }

    /// Force-abort.
    pub fn abort(&self, ceremony_id: Uuid) -> SandboxResult<()> {
        let mut g = self
            .state
            .write()
            .map_err(|_| SandboxError::Other("ceremony registry poisoned".into()))?;
        let c = g
            .ceremonies
            .get_mut(&ceremony_id)
            .ok_or_else(|| SandboxError::Other(format!("ceremony {} not found", ceremony_id)))?;
        if c.status == CeremonyStatus::Finalized {
            return Err(SandboxError::Other(
                "cannot abort finalized ceremony".into(),
            ));
        }
        c.status = CeremonyStatus::Aborted;
        Ok(())
    }

    /// Count.
    pub fn len(&self) -> usize {
        self.state.read().map(|g| g.ceremonies.len()).unwrap_or(0)
    }
    /// Empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Lookup ceremony.
    pub fn get(&self, ceremony_id: Uuid) -> Option<SigningCeremony> {
        self.state.read().ok()?.ceremonies.get(&ceremony_id).cloned()
    }
    /// Snapshot shares.
    pub fn shares(&self, ceremony_id: Uuid) -> Vec<SignatureShare> {
        self.state
            .read()
            .map(|g| g.shares.get(&ceremony_id).cloned().unwrap_or_default())
            .unwrap_or_default()
    }
    /// Lookup assembled.
    pub fn assembled(&self, ceremony_id: Uuid) -> Option<AssembledSignature> {
        self.state.read().ok()?.finalized.get(&ceremony_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    fn h(s: &str) -> Sha256Digest {
        Hasher::sha256(s.as_bytes())
    }

    fn signers() -> Vec<String> {
        vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()]
    }

    #[test]
    fn open_with_valid_threshold_works() {
        let r = CeremonyRegistry::new();
        let c = r
            .open(h("subject"), 3, signers(), "test", None)
            .unwrap();
        assert_eq!(c.threshold_m, 3);
        assert_eq!(c.total_n, 5);
        assert_eq!(c.status, CeremonyStatus::Open);
    }

    #[test]
    fn open_with_zero_threshold_errors() {
        let r = CeremonyRegistry::new();
        assert!(r.open(h("s"), 0, signers(), "x", None).is_err());
    }

    #[test]
    fn open_with_threshold_gt_signers_errors() {
        let r = CeremonyRegistry::new();
        assert!(r.open(h("s"), 10, signers(), "x", None).is_err());
    }

    #[test]
    fn open_with_duplicate_signers_errors() {
        let r = CeremonyRegistry::new();
        assert!(r
            .open(
                h("s"),
                2,
                vec!["a".into(), "a".into(), "b".into()],
                "x",
                None
            )
            .is_err());
    }

    #[test]
    fn submit_share_authorized() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n1", now()).unwrap();
        assert_eq!(r.shares(c.ceremony_id).len(), 1);
    }

    #[test]
    fn submit_unauthorized_errors() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        assert!(r.submit_share(c.ceremony_id, "ghost", "n", now()).is_err());
    }

    #[test]
    fn submit_twice_errors() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        assert!(r.submit_share(c.ceremony_id, "a", "n2", now()).is_err());
    }

    #[test]
    fn threshold_reached_status_updates() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "c", "n", now()).unwrap();
        let c2 = r.get(c.ceremony_id).unwrap();
        assert_eq!(c2.status, CeremonyStatus::ThresholdReached);
    }

    #[test]
    fn finalize_after_threshold() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "c", "n", now()).unwrap();
        let asg = r.finalize(c.ceremony_id).unwrap();
        assert_eq!(asg.share_count, 3);
        assert_eq!(asg.signer_ids.len(), 3);
        let c2 = r.get(c.ceremony_id).unwrap();
        assert_eq!(c2.status, CeremonyStatus::Finalized);
    }

    #[test]
    fn finalize_below_threshold_errors() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        assert!(r.finalize(c.ceremony_id).is_err());
    }

    #[test]
    fn finalize_idempotent() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        let a1 = r.finalize(c.ceremony_id).unwrap();
        let a2 = r.finalize(c.ceremony_id).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn submit_after_finalize_errors() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        r.finalize(c.ceremony_id).unwrap();
        assert!(r.submit_share(c.ceremony_id, "c", "n", now()).is_err());
    }

    #[test]
    fn abort_blocks_finalize() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.abort(c.ceremony_id).unwrap();
        assert!(r.finalize(c.ceremony_id).is_err());
    }

    #[test]
    fn cannot_abort_after_finalize() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        r.finalize(c.ceremony_id).unwrap();
        assert!(r.abort(c.ceremony_id).is_err());
    }

    #[test]
    fn expired_ceremony_rejects_share() {
        let r = CeremonyRegistry::new();
        let exp = OffsetDateTime::now_utc() - time::Duration::seconds(1);
        let c = r.open(h("s"), 2, signers(), "x", Some(exp)).unwrap();
        assert!(r.submit_share(c.ceremony_id, "a", "n", now()).is_err());
    }

    #[test]
    fn aggregate_hash_deterministic() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n1", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n2", now()).unwrap();
        let a1 = r.finalize(c.ceremony_id).unwrap();
        let a2 = r.assembled(c.ceremony_id).unwrap();
        assert_eq!(a1.aggregate_hash, a2.aggregate_hash);
    }

    #[test]
    fn share_commitment_includes_subject() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        let s = r
            .submit_share(c.ceremony_id, "a", "n1", now())
            .unwrap();
        // Recompute commitment.
        let mut input = Vec::new();
        input.extend_from_slice(&c.subject_hash.0);
        input.extend_from_slice(b"a");
        input.extend_from_slice(b"n1");
        let expected = Hasher::sha256(&input);
        assert_eq!(s.commitment, expected);
    }

    #[test]
    fn ceremony_serde() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 3, signers(), "x", None).unwrap();
        let j = serde_json::to_string(&c).unwrap();
        let p: SigningCeremony = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn share_serde() {
        let s = SignatureShare {
            signer_id: "a".into(),
            commitment: h("x"),
            nonce_hex: "n".into(),
            at: "2026-01-01T00:00:00Z".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let p: SignatureShare = serde_json::from_str(&j).unwrap();
        assert_eq!(p, s);
    }

    #[test]
    fn assembled_serde() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        let a = r.finalize(c.ceremony_id).unwrap();
        let j = serde_json::to_string(&a).unwrap();
        let p: AssembledSignature = serde_json::from_str(&j).unwrap();
        assert_eq!(p, a);
    }

    #[test]
    fn status_serde() {
        for s in [
            CeremonyStatus::Open,
            CeremonyStatus::ThresholdReached,
            CeremonyStatus::Finalized,
            CeremonyStatus::Aborted,
            CeremonyStatus::Expired,
        ] {
            let j = serde_json::to_string(&s).unwrap();
            let p: CeremonyStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(p, s);
        }
    }

    #[test]
    fn registry_count_and_lookup() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.get(c.ceremony_id).is_some());
        assert!(r.get(Uuid::now_v7()).is_none());
    }

    #[test]
    fn finalize_uses_first_m_shares() {
        let r = CeremonyRegistry::new();
        let c = r.open(h("s"), 2, signers(), "x", None).unwrap();
        r.submit_share(c.ceremony_id, "a", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "b", "n", now()).unwrap();
        r.submit_share(c.ceremony_id, "c", "n", now()).unwrap();
        let a = r.finalize(c.ceremony_id).unwrap();
        // Only first 2 used.
        assert_eq!(a.share_count, 2);
        assert_eq!(a.signer_ids, vec!["a", "b"]);
    }

    #[test]
    fn many_ceremonies_isolated() {
        let r = CeremonyRegistry::new();
        let c1 = r.open(h("s1"), 2, signers(), "x", None).unwrap();
        let c2 = r.open(h("s2"), 2, signers(), "x", None).unwrap();
        r.submit_share(c1.ceremony_id, "a", "n", now()).unwrap();
        assert_eq!(r.shares(c1.ceremony_id).len(), 1);
        assert_eq!(r.shares(c2.ceremony_id).len(), 0);
    }

    #[test]
    fn submit_unknown_ceremony_errors() {
        let r = CeremonyRegistry::new();
        assert!(r
            .submit_share(Uuid::now_v7(), "a", "n", now())
            .is_err());
    }

    #[test]
    fn finalize_unknown_errors() {
        let r = CeremonyRegistry::new();
        assert!(r.finalize(Uuid::now_v7()).is_err());
    }
}
