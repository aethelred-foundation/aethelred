//! Federated TEE attestation chain register.
//!
//! Distinct from [`crate::tee`] / [`crate::tee_verify`] (single-party
//! attestation primitives) and [`crate::federated_verify`] (regulator-
//! side cross-attestation report), this module captures **chains of
//! attestations across federated parties** — one chain per distributed
//! workload, with each link representing one party's TEE attestation
//! and the inter-link relationship (`Parent`, `Sibling`, `Witness`).
//!
//! Maps to the Confidential Computing Consortium's federation guidance
//! and the W3C Web Composability work on cross-domain attestation
//! provenance. Pairs with [`crate::secure_aggregation_log`] (which
//! references which chain authorised a round) and
//! [`crate::clean_room_session`] (which references the chain that
//! attested the room's TEE).
//!
//! ## Lifecycle
//!
//! `Building → Sealed → (Verified | Repudiated)`
//!
//! `Building`: links being added. `Sealed`: chain frozen, ready for
//! verification. `Verified`: cross-party verification passed.
//! `Repudiated`: at least one link failed verification.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// LinkRelation
// =============================================================================

/// Relationship of a link to the chain head / its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkRelation {
    /// First link — root of the chain.
    Root,
    /// Direct parent in a sequential chain.
    Parent,
    /// Sibling co-attestation (parallel parties at same depth).
    Sibling,
    /// Witness (third-party verifier observing).
    Witness,
}

// =============================================================================
// LinkVerdict
// =============================================================================

/// Verdict on a single link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkVerdict {
    /// Not yet verified.
    Pending,
    /// Verified.
    Verified,
    /// Failed verification.
    Failed,
    /// Skipped (e.g., quorum already achieved).
    Skipped,
}

impl LinkVerdict {
    /// True if no further verification work is expected.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

// =============================================================================
// AttestationLink
// =============================================================================

/// One TEE attestation link in the chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationLink {
    /// Stable link id within the chain.
    pub link_id: String,
    /// Party id contributing this attestation.
    pub party_id: String,
    /// TEE platform label ("Intel SGX", "AMD SEV-SNP", "AWS Nitro", "ARM CCA").
    pub platform: String,
    /// SHA-256 of the attestation document (immutable evidence).
    pub attestation_sha256: String,
    /// Optional storage URI for the attestation bytes.
    pub attestation_uri: Option<String>,
    /// Relation to the chain.
    pub relation: LinkRelation,
    /// Optional parent link id.
    pub parent_link_id: Option<String>,
    /// Verdict.
    pub verdict: LinkVerdict,
    /// Free-text verifier note.
    pub note: Option<String>,
    /// RFC 3339 — added to chain.
    pub added_at: String,
    /// RFC 3339 — verdict recorded.
    pub verified_at: Option<String>,
}

impl AttestationLink {
    /// New `Pending` link.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        link_id: impl Into<String>,
        party_id: impl Into<String>,
        platform: impl Into<String>,
        attestation_sha256: impl Into<String>,
        relation: LinkRelation,
        added_at: impl Into<String>,
    ) -> Self {
        Self {
            link_id: link_id.into(),
            party_id: party_id.into(),
            platform: platform.into(),
            attestation_sha256: attestation_sha256.into(),
            attestation_uri: None,
            relation,
            parent_link_id: None,
            verdict: LinkVerdict::Pending,
            note: None,
            added_at: added_at.into(),
            verified_at: None,
        }
    }
}

// =============================================================================
// ChainStage
// =============================================================================

/// Lifecycle stage of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStage {
    /// Links being added.
    Building,
    /// Frozen; ready to verify.
    Sealed,
    /// All required links verified.
    Verified,
    /// At least one link failed verification.
    Repudiated,
}

impl ChainStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Repudiated)
    }

    /// True if the chain currently has authority.
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Verified)
    }
}

// =============================================================================
// ChainEvent
// =============================================================================

/// One event on the chain timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: ChainStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// AttestationChain
// =============================================================================

/// One federated attestation chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationChain {
    /// Unique chain id.
    pub chain_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Federation id this chain belongs to.
    pub federation_id: String,
    /// Workload identifier ("training-round-7", "clean-room-session-12").
    pub workload_id: String,
    /// Stage.
    pub stage: ChainStage,
    /// Minimum number of `Verified` links required for chain to reach
    /// `Verified` stage.
    pub quorum: u32,
    /// Links in chain (ordered by add).
    pub links: Vec<AttestationLink>,
    /// SHA-256 of the chain head (set on Sealed).
    pub head_sha256: Option<String>,
    /// Linked aggregation round id (if any).
    pub linked_aggregation_round_id: Option<String>,
    /// Linked clean-room session id (if any).
    pub linked_clean_room_session_id: Option<String>,
    /// RFC 3339 — chain started.
    pub started_at: String,
    /// RFC 3339 — sealed.
    pub sealed_at: Option<String>,
    /// RFC 3339 — terminal.
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<ChainEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl AttestationChain {
    /// New `Building` chain.
    pub fn new(
        chain_id: impl Into<String>,
        tenant_id: impl Into<String>,
        federation_id: impl Into<String>,
        workload_id: impl Into<String>,
        quorum: u32,
        started_at: impl Into<String>,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            tenant_id: tenant_id.into(),
            federation_id: federation_id.into(),
            workload_id: workload_id.into(),
            stage: ChainStage::Building,
            quorum,
            links: Vec::new(),
            head_sha256: None,
            linked_aggregation_round_id: None,
            linked_clean_room_session_id: None,
            started_at: started_at.into(),
            sealed_at: None,
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Number of links with a Verified verdict.
    pub fn verified_link_count(&self) -> usize {
        self.links
            .iter()
            .filter(|l| matches!(l.verdict, LinkVerdict::Verified))
            .count()
    }

    /// Number of links with a Failed verdict.
    pub fn failed_link_count(&self) -> usize {
        self.links
            .iter()
            .filter(|l| matches!(l.verdict, LinkVerdict::Failed))
            .count()
    }

    /// True if at least one link has a Failed verdict.
    pub fn any_failed(&self) -> bool {
        self.failed_link_count() > 0
    }

    /// True if at least `quorum` links are Verified.
    pub fn meets_quorum(&self) -> bool {
        self.verified_link_count() >= self.quorum as usize
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ChainStage, to: ChainStage) -> bool {
    use ChainStage::*;
    matches!(
        (from, to),
        (Building, Sealed)
            | (Building, Repudiated)     // give up before sealing
            | (Sealed, Verified)
            | (Sealed, Repudiated)
    )
}

// =============================================================================
// FederatedAttestationChainRegistry
// =============================================================================

/// Thread-safe registry of federated attestation chains.
#[derive(Debug, Default)]
pub struct FederatedAttestationChainRegistry {
    inner: RwLock<HashMap<String, AttestationChain>>,
}

impl FederatedAttestationChainRegistry {
    /// New empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new chain.
    pub fn start(&self, chain: AttestationChain) -> SandboxResult<()> {
        if !matches!(chain.stage, ChainStage::Building) {
            return Err(SandboxError::Other(format!(
                "chain must start Building, got {:?}",
                chain.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        if g.contains_key(&chain.chain_id) {
            return Err(SandboxError::Other(format!(
                "chain already started: {}",
                chain.chain_id
            )));
        }
        g.insert(chain.chain_id.clone(), chain);
        Ok(())
    }

    /// Add a link to a Building chain. The first link must be `Root`;
    /// subsequent links may not be `Root`. If `parent_link_id` is set it
    /// must reference an existing link.
    pub fn add_link(&self, chain_id: &str, link: AttestationLink) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        if !matches!(c.stage, ChainStage::Building) {
            return Err(SandboxError::Other(format!(
                "cannot add link to {chain_id}: stage is {:?}",
                c.stage
            )));
        }
        if c.links.iter().any(|l| l.link_id == link.link_id) {
            return Err(SandboxError::Other(format!(
                "link already present: {}",
                link.link_id
            )));
        }
        // Root semantics.
        let is_root = matches!(link.relation, LinkRelation::Root);
        if c.links.is_empty() && !is_root {
            return Err(SandboxError::Other(format!(
                "first link must be Root, got {:?}",
                link.relation
            )));
        }
        if !c.links.is_empty() && is_root {
            return Err(SandboxError::Other(format!(
                "root link already present"
            )));
        }
        // Parent reference must exist if set.
        if let Some(parent) = &link.parent_link_id {
            if !c.links.iter().any(|l| &l.link_id == parent) {
                return Err(SandboxError::Other(format!(
                    "unknown parent_link_id: {parent}"
                )));
            }
        }
        c.links.push(link);
        Ok(())
    }

    /// Record a verdict on a link.
    pub fn record_link_verdict(
        &self,
        chain_id: &str,
        link_id: &str,
        verdict: LinkVerdict,
        at: impl Into<String>,
        note: Option<String>,
    ) -> SandboxResult<()> {
        if matches!(verdict, LinkVerdict::Pending) {
            return Err(SandboxError::Other(
                "cannot record verdict Pending".into(),
            ));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        if matches!(c.stage, ChainStage::Verified | ChainStage::Repudiated) {
            return Err(SandboxError::Other(format!(
                "cannot record verdict on {chain_id}: stage is {:?}",
                c.stage
            )));
        }
        let l = c
            .links
            .iter_mut()
            .find(|l| l.link_id == link_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown link {link_id}")))?;
        if l.verdict.is_resolved() {
            return Err(SandboxError::Other(format!(
                "link {link_id} already resolved"
            )));
        }
        l.verdict = verdict;
        l.verified_at = Some(at.into());
        if let Some(n) = note {
            l.note = Some(n);
        }
        Ok(())
    }

    /// Seal the chain (Building → Sealed). Sets the head SHA.
    pub fn seal(
        &self,
        chain_id: &str,
        head_sha256: impl Into<String>,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AttestationChain> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        if !legal_transition(c.stage, ChainStage::Sealed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Sealed",
                c.stage
            )));
        }
        if c.links.is_empty() {
            return Err(SandboxError::Other(format!(
                "cannot seal {chain_id}: no links"
            )));
        }
        let when = at.into();
        c.stage = ChainStage::Sealed;
        c.sealed_at = Some(when.clone());
        c.head_sha256 = Some(head_sha256.into());
        c.events.push(ChainEvent {
            at: when,
            actor: actor.into(),
            stage: ChainStage::Sealed,
            note: format!("sealed with {} link(s)", c.links.len()),
        });
        Ok(c.clone())
    }

    /// Finalise the chain to Verified or Repudiated based on verdicts.
    /// `Verified` requires at least `quorum` Verified links and zero
    /// Failed links. Otherwise → `Repudiated`.
    pub fn finalise(
        &self,
        chain_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AttestationChain> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        if !matches!(c.stage, ChainStage::Sealed) {
            return Err(SandboxError::Other(format!(
                "cannot finalise {chain_id}: stage is {:?}",
                c.stage
            )));
        }
        let new_stage = if c.any_failed() || !c.meets_quorum() {
            ChainStage::Repudiated
        } else {
            ChainStage::Verified
        };
        let when = at.into();
        c.stage = new_stage;
        c.closed_at = Some(when.clone());
        c.events.push(ChainEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: format!(
                "verified={}, failed={}, quorum={}",
                c.verified_link_count(),
                c.failed_link_count(),
                c.quorum
            ),
        });
        Ok(c.clone())
    }

    /// Repudiate the chain (any non-terminal stage).
    pub fn repudiate(
        &self,
        chain_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<AttestationChain> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        if !legal_transition(c.stage, ChainStage::Repudiated) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Repudiated",
                c.stage
            )));
        }
        let when = at.into();
        c.stage = ChainStage::Repudiated;
        c.closed_at = Some(when.clone());
        c.events.push(ChainEvent {
            at: when,
            actor: actor.into(),
            stage: ChainStage::Repudiated,
            note: reason.into(),
        });
        Ok(c.clone())
    }

    /// Link an aggregation-round id.
    pub fn link_aggregation_round(
        &self,
        chain_id: &str,
        round_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        c.linked_aggregation_round_id = Some(round_id.into());
        Ok(())
    }

    /// Link a clean-room session id.
    pub fn link_clean_room_session(
        &self,
        chain_id: &str,
        session_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        c.linked_clean_room_session_id = Some(session_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, chain_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("attestation chain registry poisoned".into()))?;
        let c = g
            .get_mut(chain_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown chain {chain_id}")))?;
        let tag = tag.into();
        if !c.tags.contains(&tag) {
            c.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, chain_id: &str) -> Option<AttestationChain> {
        let g = self.inner.read().ok()?;
        g.get(chain_id).cloned()
    }

    /// All chains.
    pub fn all(&self) -> Vec<AttestationChain> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<AttestationChain> {
        self.all()
            .into_iter()
            .filter(|c| c.tenant_id == tenant_id)
            .collect()
    }

    /// For a federation.
    pub fn for_federation(&self, federation_id: &str) -> Vec<AttestationChain> {
        self.all()
            .into_iter()
            .filter(|c| c.federation_id == federation_id)
            .collect()
    }

    /// For a workload.
    pub fn for_workload(&self, workload_id: &str) -> Vec<AttestationChain> {
        self.all()
            .into_iter()
            .filter(|c| c.workload_id == workload_id)
            .collect()
    }

    /// By stage.
    pub fn by_stage(&self, stage: ChainStage) -> Vec<AttestationChain> {
        self.all().into_iter().filter(|c| c.stage == stage).collect()
    }

    /// Currently authoritative chains.
    pub fn authoritative(&self) -> Vec<AttestationChain> {
        self.all()
            .into_iter()
            .filter(|c| c.stage.is_authoritative())
            .collect()
    }

    /// Number of chains.
    pub fn count(&self) -> usize {
        self.inner.read().map(|g| g.len()).unwrap_or(0)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(id: &str, federation: &str, quorum: u32) -> AttestationChain {
        AttestationChain::new(
            id,
            "tenant-orch",
            federation,
            "training-round-7",
            quorum,
            "2025-04-15T00:00:00Z",
        )
    }

    fn link(
        id: &str,
        party: &str,
        relation: LinkRelation,
        parent: Option<&str>,
    ) -> AttestationLink {
        let mut l = AttestationLink::new(
            id,
            party,
            "Intel SGX",
            format!("sha-{id}"),
            relation,
            "2025-04-15T00:01:00Z",
        );
        if let Some(p) = parent {
            l.parent_link_id = Some(p.into());
        }
        l
    }

    #[test]
    fn start_and_get() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        assert!(r.get("c1").is_some());
    }

    #[test]
    fn duplicate_start_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        let err = r.start(chain("c1", "fed-1", 2)).unwrap_err();
        assert!(format!("{err}").contains("already started"));
    }

    #[test]
    fn must_start_building() {
        let mut c = chain("c1", "fed-1", 2);
        c.stage = ChainStage::Sealed;
        let r = FederatedAttestationChainRegistry::new();
        let err = r.start(c).unwrap_err();
        assert!(format!("{err}").contains("must start Building"));
    }

    #[test]
    fn first_link_must_be_root() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        let err = r
            .add_link("c1", link("l1", "p1", LinkRelation::Sibling, None))
            .unwrap_err();
        assert!(format!("{err}").contains("first link must be Root"));
    }

    #[test]
    fn root_only_once() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        let err = r
            .add_link("c1", link("l1", "p1", LinkRelation::Root, None))
            .unwrap_err();
        assert!(format!("{err}").contains("root link already present"));
    }

    #[test]
    fn parent_link_must_exist() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        let err = r
            .add_link(
                "c1",
                link("l1", "p1", LinkRelation::Parent, Some("ghost")),
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown parent_link_id"));
    }

    #[test]
    fn add_link_dedupes_id() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        let err = r
            .add_link("c1", link("l0", "p1", LinkRelation::Sibling, None))
            .unwrap_err();
        assert!(format!("{err}").contains("already present"));
    }

    #[test]
    fn add_link_after_sealed_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.seal("c1", "head-sha", "verifier", "2025-04-15T01:00:00Z").unwrap();
        let err = r
            .add_link("c1", link("l1", "p1", LinkRelation::Sibling, None))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot add link"));
    }

    #[test]
    fn happy_path_verified() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.add_link(
            "c1",
            link("l1", "p1", LinkRelation::Sibling, Some("l0")),
        )
        .unwrap();
        r.add_link(
            "c1",
            link("l2", "p2", LinkRelation::Sibling, Some("l0")),
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l1",
            LinkVerdict::Verified,
            "2025-04-15T00:31:00Z",
            None,
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l2",
            LinkVerdict::Skipped,
            "2025-04-15T00:32:00Z",
            None,
        )
        .unwrap();
        r.seal("c1", "head-sha", "verifier", "2025-04-15T01:00:00Z").unwrap();
        let c = r.finalise("c1", "verifier", "2025-04-15T01:01:00Z").unwrap();
        assert_eq!(c.stage, ChainStage::Verified);
        assert!(c.stage.is_authoritative());
        assert_eq!(c.verified_link_count(), 2);
    }

    #[test]
    fn finalise_below_quorum_repudiates() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 3)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.add_link(
            "c1",
            link("l1", "p1", LinkRelation::Sibling, Some("l0")),
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l1",
            LinkVerdict::Verified,
            "2025-04-15T00:31:00Z",
            None,
        )
        .unwrap();
        r.seal("c1", "head-sha", "verifier", "2025-04-15T01:00:00Z").unwrap();
        let c = r.finalise("c1", "verifier", "2025-04-15T01:01:00Z").unwrap();
        // Only 2 verified, quorum 3 → Repudiated
        assert_eq!(c.stage, ChainStage::Repudiated);
        assert!(!c.stage.is_authoritative());
    }

    #[test]
    fn finalise_failed_link_repudiates() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.add_link(
            "c1",
            link("l1", "p1", LinkRelation::Sibling, Some("l0")),
        )
        .unwrap();
        r.add_link(
            "c1",
            link("l2", "p2", LinkRelation::Sibling, Some("l0")),
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l1",
            LinkVerdict::Verified,
            "2025-04-15T00:31:00Z",
            None,
        )
        .unwrap();
        r.record_link_verdict(
            "c1",
            "l2",
            LinkVerdict::Failed,
            "2025-04-15T00:32:00Z",
            Some("revocation".into()),
        )
        .unwrap();
        r.seal("c1", "head-sha", "verifier", "2025-04-15T01:00:00Z").unwrap();
        let c = r.finalise("c1", "verifier", "2025-04-15T01:01:00Z").unwrap();
        // Quorum reached but failed link present → Repudiated
        assert_eq!(c.stage, ChainStage::Repudiated);
    }

    #[test]
    fn seal_requires_links() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        let err = r.seal("c1", "head-sha", "v", "2025-04-15T01:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("no links"));
    }

    #[test]
    fn record_verdict_pending_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        let err = r
            .record_link_verdict(
                "c1",
                "l0",
                LinkVerdict::Pending,
                "2025-04-15T00:30:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("verdict Pending"));
    }

    #[test]
    fn record_verdict_already_resolved_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        let err = r
            .record_link_verdict(
                "c1",
                "l0",
                LinkVerdict::Failed,
                "2025-04-15T00:31:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("already resolved"));
    }

    #[test]
    fn record_verdict_unknown_link_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        let err = r
            .record_link_verdict(
                "c1",
                "ghost",
                LinkVerdict::Verified,
                "2025-04-15T00:30:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("unknown link"));
    }

    #[test]
    fn record_verdict_after_terminal_errors() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        r.seal("c1", "head", "v", "2025-04-15T01:00:00Z").unwrap();
        r.finalise("c1", "v", "2025-04-15T01:01:00Z").unwrap();
        // Add a new link via direct mutation isn't possible; test
        // record_link_verdict on a non-existent path through state.
        // Already in Verified stage — try again.
        let err = r
            .record_link_verdict(
                "c1",
                "l0",
                LinkVerdict::Failed,
                "2025-04-15T01:02:00Z",
                None,
            )
            .unwrap_err();
        assert!(format!("{err}").contains("cannot record verdict"));
    }

    #[test]
    fn repudiate_from_building() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        let c = r.repudiate(
            "c1",
            "v",
            "2025-04-15T00:30:00Z",
            "abandoned",
        ).unwrap();
        assert_eq!(c.stage, ChainStage::Repudiated);
    }

    #[test]
    fn repudiate_from_sealed() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.seal("c1", "head", "v", "2025-04-15T01:00:00Z").unwrap();
        let c = r
            .repudiate("c1", "v", "2025-04-15T01:30:00Z", "fault detected")
            .unwrap();
        assert_eq!(c.stage, ChainStage::Repudiated);
    }

    #[test]
    fn link_aggregation_round_session() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.link_aggregation_round("c1", "AGG-007").unwrap();
        r.link_clean_room_session("c1", "ROOM-42").unwrap();
        let c = r.get("c1").unwrap();
        assert_eq!(c.linked_aggregation_round_id.as_deref(), Some("AGG-007"));
        assert_eq!(c.linked_clean_room_session_id.as_deref(), Some("ROOM-42"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 2)).unwrap();
        r.add_tag("c1", "tee").unwrap();
        r.add_tag("c1", "tee").unwrap();
        r.add_tag("c1", "production").unwrap();
        assert_eq!(r.get("c1").unwrap().tags, vec!["tee", "production"]);
    }

    #[test]
    fn unknown_chain_errors() {
        let r = FederatedAttestationChainRegistry::new();
        let err = r.add_tag("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown chain"));
    }

    #[test]
    fn for_tenant_federation_workload_filters() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        let mut other = chain("c2", "fed-2", 1);
        other.tenant_id = "tenant-other".into();
        other.workload_id = "training-round-8".into();
        r.start(other).unwrap();
        assert_eq!(r.for_tenant("tenant-orch").len(), 1);
        assert_eq!(r.for_tenant("tenant-other").len(), 1);
        assert_eq!(r.for_federation("fed-1").len(), 1);
        assert_eq!(r.for_workload("training-round-7").len(), 1);
        assert_eq!(r.for_workload("training-round-8").len(), 1);
    }

    #[test]
    fn authoritative_filter() {
        let r = FederatedAttestationChainRegistry::new();
        r.start(chain("c1", "fed-1", 1)).unwrap();
        r.add_link("c1", link("l0", "p0", LinkRelation::Root, None)).unwrap();
        r.record_link_verdict(
            "c1",
            "l0",
            LinkVerdict::Verified,
            "2025-04-15T00:30:00Z",
            None,
        )
        .unwrap();
        r.seal("c1", "head", "v", "2025-04-15T01:00:00Z").unwrap();
        r.finalise("c1", "v", "2025-04-15T01:01:00Z").unwrap();
        r.start(chain("c2", "fed-1", 1)).unwrap();
        assert_eq!(r.authoritative().len(), 1);
        assert_eq!(r.authoritative()[0].chain_id, "c1");
    }

    #[test]
    fn meets_quorum_helper() {
        let mut c = chain("c1", "fed-1", 2);
        c.links.push(link("l0", "p0", LinkRelation::Root, None));
        c.links[0].verdict = LinkVerdict::Verified;
        assert!(!c.meets_quorum());
        c.links.push(link("l1", "p1", LinkRelation::Sibling, None));
        c.links[1].verdict = LinkVerdict::Verified;
        assert!(c.meets_quorum());
    }

    #[test]
    fn stage_helpers() {
        for s in [ChainStage::Verified, ChainStage::Repudiated] {
            assert!(s.is_terminal());
        }
        assert!(ChainStage::Verified.is_authoritative());
        assert!(!ChainStage::Repudiated.is_authoritative());
        assert!(!ChainStage::Building.is_terminal());
    }

    #[test]
    fn count_tracks() {
        let r = FederatedAttestationChainRegistry::new();
        assert_eq!(r.count(), 0);
        r.start(chain("c1", "fed-1", 1)).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn chain_serde() {
        let c = chain("c1", "fed-1", 2);
        let j = serde_json::to_string(&c).unwrap();
        let back: AttestationChain = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enums_serde() {
        for r in [
            LinkRelation::Root,
            LinkRelation::Parent,
            LinkRelation::Sibling,
            LinkRelation::Witness,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<LinkRelation>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
        for v in [
            LinkVerdict::Pending,
            LinkVerdict::Verified,
            LinkVerdict::Failed,
            LinkVerdict::Skipped,
        ] {
            assert_eq!(
                v,
                serde_json::from_str::<LinkVerdict>(&serde_json::to_string(&v).unwrap()).unwrap()
            );
        }
        for s in [
            ChainStage::Building,
            ChainStage::Sealed,
            ChainStage::Verified,
            ChainStage::Repudiated,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ChainStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
    }
}
