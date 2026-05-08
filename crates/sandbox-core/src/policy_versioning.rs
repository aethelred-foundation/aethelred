//! Versioned policies with effective-dating + rollback.
//!
//! Auditors don't just ask "what is your policy?" They ask "what policy was
//! in effect at 14:32 UTC on 17 March 2024 when this loan was decisioned?"
//! That requires:
//!
//! 1. **Append-only history.** Every policy change creates a new
//!    [`PolicyVersion`]; old versions are never deleted.
//! 2. **Effective dating.** Each version declares `effective_from` and
//!    optional `effective_to` so a policy *as of timestamp T* can be looked
//!    up deterministically.
//! 3. **Tamper-evident chain.** Each version links to the prior version's
//!    hash; an attacker who modifies any version breaks the chain.
//! 4. **Rollback.** An operator can introduce a new version that mirrors an
//!    earlier state without losing the audit trail of the rollback action.
//!
//! ## Lookup semantics
//!
//! [`PolicyVersionLog::policy_at`] returns the version whose
//! `effective_from <= ts < effective_to` (with `effective_to == None` meaning
//! "still in effect"). If multiple versions overlap (mis-configuration), the
//! one with the latest `effective_from` wins — last-writer-wins on the
//! effective ordering.

use crate::hashing::{Hasher, Sha256Digest};
use crate::policy_dsl::PolicyDocument;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// PolicyVersion
// =============================================================================

/// One version of a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Stable id (e.g., `"po_soc2_type2"`).
    pub policy_id: String,
    /// Sequential version number (1, 2, 3, ...).
    pub version: u32,
    /// RFC 3339 effective-from time.
    pub effective_from: String,
    /// Optional RFC 3339 effective-to time.
    pub effective_to: Option<String>,
    /// Author of the change.
    pub author: String,
    /// Optional change-management ticket id.
    pub change_ticket: Option<String>,
    /// Free-text rationale.
    pub rationale: Option<String>,
    /// The policy document itself.
    pub document: PolicyDocument,
    /// Hash of prior version (None for v1).
    pub prior_hash: Option<Sha256Digest>,
    /// Hash of *this* version's content (excluding `version_hash`).
    pub version_hash: Sha256Digest,
}

impl PolicyVersion {
    fn compute_hash(
        policy_id: &str,
        version: u32,
        effective_from: &str,
        effective_to: Option<&str>,
        author: &str,
        document: &PolicyDocument,
        prior: Option<&Sha256Digest>,
    ) -> Sha256Digest {
        let mut input = Vec::new();
        input.extend_from_slice(policy_id.as_bytes());
        input.push(0);
        input.extend_from_slice(&version.to_le_bytes());
        input.extend_from_slice(effective_from.as_bytes());
        input.push(0);
        if let Some(t) = effective_to {
            input.extend_from_slice(t.as_bytes());
        }
        input.push(0);
        input.extend_from_slice(author.as_bytes());
        input.push(0);
        let doc_json = serde_json::to_vec(document).unwrap_or_default();
        input.extend_from_slice(&doc_json);
        if let Some(p) = prior {
            input.extend_from_slice(&p.0);
        }
        Hasher::sha256(&input)
    }
}

// =============================================================================
// PublishOptions
// =============================================================================

/// Options for publishing a new version.
#[derive(Debug, Clone, Default)]
pub struct PublishOptions {
    /// Effective-from time — defaults to now if omitted.
    pub effective_from: Option<OffsetDateTime>,
    /// Optional change-management ticket.
    pub change_ticket: Option<String>,
    /// Optional rationale.
    pub rationale: Option<String>,
}

// =============================================================================
// PolicyVersionLog
// =============================================================================

/// Append-only log of versions for one or more policies.
#[derive(Default)]
pub struct PolicyVersionLog {
    versions: RwLock<Vec<PolicyVersion>>,
}

impl std::fmt::Debug for PolicyVersionLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyVersionLog")
            .field(
                "versions",
                &self.versions.read().map(|g| g.len()).unwrap_or(0),
            )
            .finish()
    }
}

impl PolicyVersionLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new version of `policy_id`.
    ///
    /// - Auto-assigns the next sequence number per policy_id.
    /// - Closes the previous version's `effective_to` to the new one's
    ///   `effective_from` so windows don't overlap.
    pub fn publish(
        &self,
        document: PolicyDocument,
        author: impl Into<String>,
        opts: PublishOptions,
    ) -> SandboxResult<PolicyVersion> {
        let author = author.into();
        let policy_id = document.policy_id.clone();
        let now = opts.effective_from.unwrap_or_else(OffsetDateTime::now_utc);
        let effective_from = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();

        let mut g = self
            .versions
            .write()
            .map_err(|_| SandboxError::Other("policy version log poisoned".into()))?;

        // Find prior version of this policy_id.
        let prior = g
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .max_by_key(|v| v.version)
            .cloned();

        let version = prior.as_ref().map(|p| p.version + 1).unwrap_or(1);
        let prior_hash = prior.as_ref().map(|p| p.version_hash.clone());

        // Close out previous version's effective_to (only if it doesn't already have one).
        if let Some(prev) = prior.as_ref() {
            if prev.effective_to.is_none() {
                if let Some(slot) = g.iter_mut().find(|v| {
                    v.policy_id == policy_id && v.version == prev.version
                }) {
                    slot.effective_to = Some(effective_from.clone());
                    // Recompute prior version's hash since effective_to changed.
                    slot.version_hash = PolicyVersion::compute_hash(
                        &slot.policy_id,
                        slot.version,
                        &slot.effective_from,
                        slot.effective_to.as_deref(),
                        &slot.author,
                        &slot.document,
                        slot.prior_hash.as_ref(),
                    );
                }
            }
        }

        // Recompute prior_hash to point to the (possibly updated) prior version.
        let prior_hash_after_update = g
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .max_by_key(|v| v.version)
            .map(|p| p.version_hash.clone())
            .or(prior_hash);

        let version_hash = PolicyVersion::compute_hash(
            &policy_id,
            version,
            &effective_from,
            None,
            &author,
            &document,
            prior_hash_after_update.as_ref(),
        );

        let pv = PolicyVersion {
            policy_id,
            version,
            effective_from,
            effective_to: None,
            author,
            change_ticket: opts.change_ticket,
            rationale: opts.rationale,
            document,
            prior_hash: prior_hash_after_update,
            version_hash,
        };
        g.push(pv.clone());
        Ok(pv)
    }

    /// Roll back to a previous version by republishing it as a new version.
    /// The original version is preserved unchanged; the rollback shows up as
    /// a fresh entry with `rationale = "rollback to vN"`.
    pub fn rollback(
        &self,
        policy_id: &str,
        target_version: u32,
        author: impl Into<String>,
    ) -> SandboxResult<PolicyVersion> {
        let target = {
            let g = self
                .versions
                .read()
                .map_err(|_| SandboxError::Other("policy version log poisoned".into()))?;
            g.iter()
                .find(|v| v.policy_id == policy_id && v.version == target_version)
                .cloned()
        };
        let target = target.ok_or_else(|| {
            SandboxError::Other(format!(
                "rollback: no version {} of policy {}",
                target_version, policy_id
            ))
        })?;
        self.publish(
            target.document.clone(),
            author,
            PublishOptions {
                effective_from: None,
                change_ticket: None,
                rationale: Some(format!("rollback to v{}", target_version)),
            },
        )
    }

    /// Look up the version active at `ts`.
    pub fn policy_at(
        &self,
        policy_id: &str,
        ts: OffsetDateTime,
    ) -> SandboxResult<Option<PolicyVersion>> {
        let ts_str = ts
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let g = self
            .versions
            .read()
            .map_err(|_| SandboxError::Other("policy version log poisoned".into()))?;
        let mut active: Option<&PolicyVersion> = None;
        for v in g.iter().filter(|v| v.policy_id == policy_id) {
            if v.effective_from.as_str() > ts_str.as_str() {
                continue;
            }
            if let Some(eto) = &v.effective_to {
                if eto.as_str() <= ts_str.as_str() {
                    continue;
                }
            }
            // Last-writer-wins on effective_from ordering.
            match active {
                None => active = Some(v),
                Some(cur) if v.effective_from > cur.effective_from => active = Some(v),
                _ => {}
            }
        }
        Ok(active.cloned())
    }

    /// Return all versions of one policy in version-number order.
    pub fn history(&self, policy_id: &str) -> Vec<PolicyVersion> {
        let g = match self.versions.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let mut v: Vec<PolicyVersion> = g
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .cloned()
            .collect();
        v.sort_by_key(|v| v.version);
        v
    }

    /// Return the latest version of a policy (by version number).
    pub fn latest(&self, policy_id: &str) -> Option<PolicyVersion> {
        self.versions
            .read()
            .ok()?
            .iter()
            .filter(|v| v.policy_id == policy_id)
            .max_by_key(|v| v.version)
            .cloned()
    }

    /// Total number of versions across all policies.
    pub fn len(&self) -> usize {
        self.versions.read().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Verify the chain integrity for one policy_id: every version's
    /// `prior_hash` matches the prior version's `version_hash`, and every
    /// version's recomputed hash matches.
    pub fn verify_chain(&self, policy_id: &str) -> SandboxResult<()> {
        let g = self
            .versions
            .read()
            .map_err(|_| SandboxError::Other("policy version log poisoned".into()))?;
        let mut versions: Vec<&PolicyVersion> = g.iter().filter(|v| v.policy_id == policy_id).collect();
        versions.sort_by_key(|v| v.version);
        let mut prior: Option<&Sha256Digest> = None;
        for v in versions {
            // Prior link.
            match (&v.prior_hash, prior) {
                (None, None) => {}
                (Some(a), Some(b)) if a == b => {}
                _ => {
                    return Err(SandboxError::Other(format!(
                        "policy {} chain break at v{}",
                        policy_id, v.version
                    )))
                }
            }
            // Self-hash.
            let recomputed = PolicyVersion::compute_hash(
                &v.policy_id,
                v.version,
                &v.effective_from,
                v.effective_to.as_deref(),
                &v.author,
                &v.document,
                v.prior_hash.as_ref(),
            );
            if recomputed != v.version_hash {
                return Err(SandboxError::Other(format!(
                    "policy {} v{} hash mismatch",
                    policy_id, v.version
                )));
            }
            prior = Some(&v.version_hash);
        }
        Ok(())
    }
}

// =============================================================================
// EffectiveDateRange
// =============================================================================

/// Helper representing a version's effective window for tooling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EffectiveDateRange {
    /// Policy id.
    pub policy_id: String,
    /// Version.
    pub version: u32,
    /// RFC 3339 from.
    pub from: String,
    /// RFC 3339 to (or None for open-ended).
    pub to: Option<String>,
    /// Stable id for audit refs.
    pub trace_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_dsl::{DslGate, GateSeverity, PolicyDocument};

    fn doc(policy_id: &str, gate_id: &str) -> PolicyDocument {
        PolicyDocument {
            schema_version: 1,
            policy_id: policy_id.into(),
            owner: "compliance".into(),
            effective_from: None,
            effective_to: None,
            gates: vec![DslGate {
                id: gate_id.into(),
                name: gate_id.into(),
                rule: "always-true".into(),
                severity: GateSeverity::Required,
                tags: vec![],
                regulators: vec![],
            }],
        }
    }

    #[test]
    fn empty_log_is_empty() {
        let log = PolicyVersionLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn publish_assigns_v1() {
        let log = PolicyVersionLog::new();
        let v = log
            .publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        assert_eq!(v.version, 1);
        assert!(v.prior_hash.is_none());
    }

    #[test]
    fn second_publish_assigns_v2_and_chains() {
        let log = PolicyVersionLog::new();
        let v1 = log
            .publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        let v2 = log
            .publish(doc("p", "g2"), "alice", PublishOptions::default())
            .unwrap();
        assert_eq!(v2.version, 2);
        // prior_hash should chain — but v1's hash may have been updated when v2
        // closed v1's effective_to. Reload v1 from history.
        let history = log.history("p");
        assert_eq!(history.len(), 2);
        assert_eq!(v2.prior_hash.as_ref(), Some(&history[0].version_hash));
        let _ = v1;
    }

    #[test]
    fn first_version_effective_to_closed_on_second_publish() {
        let log = PolicyVersionLog::new();
        log.publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        log.publish(doc("p", "g2"), "alice", PublishOptions::default())
            .unwrap();
        let history = log.history("p");
        assert!(history[0].effective_to.is_some());
        assert!(history[1].effective_to.is_none());
    }

    #[test]
    fn policy_at_within_window_returns_active() {
        let log = PolicyVersionLog::new();
        let now = OffsetDateTime::now_utc();
        log.publish(
            doc("p", "g1"),
            "alice",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(10)),
                ..Default::default()
            },
        )
        .unwrap();
        log.publish(
            doc("p", "g2"),
            "bob",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(1)),
                ..Default::default()
            },
        )
        .unwrap();
        // 5 days ago — should hit v1.
        let q = now - time::Duration::days(5);
        let p = log.policy_at("p", q).unwrap().unwrap();
        assert_eq!(p.version, 1);
    }

    #[test]
    fn policy_at_after_latest_returns_latest() {
        let log = PolicyVersionLog::new();
        let now = OffsetDateTime::now_utc();
        log.publish(
            doc("p", "g1"),
            "alice",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(10)),
                ..Default::default()
            },
        )
        .unwrap();
        let p = log.policy_at("p", now).unwrap().unwrap();
        assert_eq!(p.version, 1);
    }

    #[test]
    fn policy_at_before_first_returns_none() {
        let log = PolicyVersionLog::new();
        let now = OffsetDateTime::now_utc();
        log.publish(
            doc("p", "g1"),
            "alice",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(5)),
                ..Default::default()
            },
        )
        .unwrap();
        let q = now - time::Duration::days(20);
        assert!(log.policy_at("p", q).unwrap().is_none());
    }

    #[test]
    fn policy_at_unknown_returns_none() {
        let log = PolicyVersionLog::new();
        let now = OffsetDateTime::now_utc();
        assert!(log.policy_at("ghost", now).unwrap().is_none());
    }

    #[test]
    fn history_returns_all_versions_for_policy() {
        let log = PolicyVersionLog::new();
        for i in 0..3 {
            log.publish(
                doc("p", &format!("g{i}")),
                "a",
                PublishOptions::default(),
            )
            .unwrap();
        }
        let h = log.history("p");
        assert_eq!(h.len(), 3);
        assert!(h.iter().enumerate().all(|(i, v)| v.version == (i + 1) as u32));
    }

    #[test]
    fn latest_returns_highest_version() {
        let log = PolicyVersionLog::new();
        for _ in 0..5 {
            log.publish(doc("p", "g"), "a", PublishOptions::default())
                .unwrap();
        }
        let latest = log.latest("p").unwrap();
        assert_eq!(latest.version, 5);
    }

    #[test]
    fn rollback_creates_new_version_with_old_doc() {
        let log = PolicyVersionLog::new();
        log.publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        log.publish(doc("p", "g2"), "alice", PublishOptions::default())
            .unwrap();
        let rolled = log.rollback("p", 1, "ops").unwrap();
        assert_eq!(rolled.version, 3);
        assert_eq!(rolled.document.gates[0].id, "g1");
        assert_eq!(rolled.rationale.as_deref(), Some("rollback to v1"));
    }

    #[test]
    fn rollback_unknown_target_errors() {
        let log = PolicyVersionLog::new();
        log.publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        assert!(log.rollback("p", 99, "ops").is_err());
    }

    #[test]
    fn verify_chain_after_writes_ok() {
        let log = PolicyVersionLog::new();
        for i in 0..5 {
            log.publish(
                doc("p", &format!("g{i}")),
                "a",
                PublishOptions::default(),
            )
            .unwrap();
        }
        log.verify_chain("p").unwrap();
    }

    #[test]
    fn verify_chain_unknown_policy_ok() {
        let log = PolicyVersionLog::new();
        log.verify_chain("ghost").unwrap();
    }

    #[test]
    fn verify_chain_after_rollback_ok() {
        let log = PolicyVersionLog::new();
        log.publish(doc("p", "g1"), "alice", PublishOptions::default())
            .unwrap();
        log.publish(doc("p", "g2"), "alice", PublishOptions::default())
            .unwrap();
        log.rollback("p", 1, "ops").unwrap();
        log.verify_chain("p").unwrap();
    }

    #[test]
    fn versions_isolated_across_policy_ids() {
        let log = PolicyVersionLog::new();
        log.publish(doc("p1", "g"), "a", PublishOptions::default())
            .unwrap();
        log.publish(doc("p2", "g"), "a", PublishOptions::default())
            .unwrap();
        let v3 = log
            .publish(doc("p1", "g"), "a", PublishOptions::default())
            .unwrap();
        // p1 should be at v2, p2 at v1.
        assert_eq!(v3.version, 2);
        assert_eq!(log.latest("p2").unwrap().version, 1);
    }

    #[test]
    fn publish_with_change_ticket_records_it() {
        let log = PolicyVersionLog::new();
        let v = log
            .publish(
                doc("p", "g"),
                "alice",
                PublishOptions {
                    change_ticket: Some("CHG-100".into()),
                    rationale: Some("annual review".into()),
                    effective_from: None,
                },
            )
            .unwrap();
        assert_eq!(v.change_ticket.as_deref(), Some("CHG-100"));
        assert_eq!(v.rationale.as_deref(), Some("annual review"));
    }

    #[test]
    fn version_serde_round_trip() {
        let log = PolicyVersionLog::new();
        let v = log
            .publish(doc("p", "g"), "alice", PublishOptions::default())
            .unwrap();
        let j = serde_json::to_string(&v).unwrap();
        let p: PolicyVersion = serde_json::from_str(&j).unwrap();
        // PolicyDocument doesn't implement PartialEq, so compare by hash + ids.
        assert_eq!(p.version_hash, v.version_hash);
        assert_eq!(p.policy_id, v.policy_id);
        assert_eq!(p.version, v.version);
    }

    #[test]
    fn policy_at_with_two_overlapping_returns_latest_effective() {
        let log = PolicyVersionLog::new();
        let now = OffsetDateTime::now_utc();
        // V1 effective from 10 days ago.
        log.publish(
            doc("p", "g1"),
            "a",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(10)),
                ..Default::default()
            },
        )
        .unwrap();
        // V2 effective from 5 days ago.
        log.publish(
            doc("p", "g2"),
            "a",
            PublishOptions {
                effective_from: Some(now - time::Duration::days(5)),
                ..Default::default()
            },
        )
        .unwrap();
        // Query at "now" should return v2.
        let p = log.policy_at("p", now).unwrap().unwrap();
        assert_eq!(p.version, 2);
    }

    #[test]
    fn history_returns_empty_for_unknown_policy() {
        let log = PolicyVersionLog::new();
        assert!(log.history("ghost").is_empty());
    }

    #[test]
    fn latest_unknown_returns_none() {
        let log = PolicyVersionLog::new();
        assert!(log.latest("ghost").is_none());
    }

    #[test]
    fn publish_options_default_uses_now() {
        let log = PolicyVersionLog::new();
        let v = log
            .publish(doc("p", "g"), "a", PublishOptions::default())
            .unwrap();
        assert!(!v.effective_from.is_empty());
    }

    #[test]
    fn many_versions_chain_intact() {
        let log = PolicyVersionLog::new();
        for i in 0..30 {
            log.publish(
                doc("p", &format!("g{i}")),
                "a",
                PublishOptions::default(),
            )
            .unwrap();
        }
        log.verify_chain("p").unwrap();
        assert_eq!(log.history("p").len(), 30);
    }

    #[test]
    fn effective_date_range_serde() {
        let r = EffectiveDateRange {
            policy_id: "p".into(),
            version: 1,
            from: "2026-01-01T00:00:00Z".into(),
            to: None,
            trace_id: Uuid::now_v7(),
        };
        let j = serde_json::to_string(&r).unwrap();
        let p: EffectiveDateRange = serde_json::from_str(&j).unwrap();
        assert_eq!(p, r);
    }
}
