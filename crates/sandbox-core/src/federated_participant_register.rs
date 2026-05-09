//! Federated learning / multi-party participant register.
//!
//! Distinct from [`crate::customer_consent`] (per-end-user product
//! consent) and [`crate::federated_verify`] (regulator-side cross-party
//! attestation), this is the **per-participant enrolment record** that
//! tracks every data-contributing party in a federated learning round
//! or secure multi-party computation:
//!
//! - the **legal entity** contributing data,
//! - the **scope** of consent (training rounds, model output access),
//! - the **contribution metadata** (sample-count, weight),
//! - the **lifecycle** (`Invited → Enrolled → Active → (Suspended ↔
//!   Active) → Withdrawn | Terminated`).
//!
//! Maps to the federated-AI governance frameworks emerging in HHS
//! (HIPAA cohort sharing), EU AI Act Art 26 (importer obligations),
//! and the Confidential Computing Consortium's federation guidance.

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// ParticipantStage
// =============================================================================

/// Lifecycle stage of a federated participant enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStage {
    /// Invited but not yet accepted.
    Invited,
    /// Enrolment paperwork (DPA / consortium agreement) signed.
    Enrolled,
    /// Actively contributing in current rounds.
    Active,
    /// Temporarily suspended (e.g., audit, network outage).
    Suspended,
    /// Voluntarily withdrew.
    Withdrawn,
    /// Forcibly terminated by the orchestrator (policy violation).
    Terminated,
}

impl ParticipantStage {
    /// True if the participant is currently contributing.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Withdrawn | Self::Terminated)
    }
}

// =============================================================================
// ConsentScope
// =============================================================================

/// Documented scope of the participant's consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentScope {
    /// Single training round only.
    SingleRound,
    /// Multiple rounds within a defined cohort study.
    CohortStudy,
    /// Continuous training while membership active.
    Continuous,
    /// Bench-only (eval / validation, not training).
    BenchOnly,
}

// =============================================================================
// ContributionMode
// =============================================================================

/// How the participant contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionMode {
    /// Local training on their data; gradients shared.
    LocalTraining,
    /// Encrypted data shared via secure aggregation.
    SecureAggregation,
    /// Differential-privacy noise applied locally.
    DpLocal,
    /// Differential-privacy applied centrally (trust the aggregator).
    DpCentral,
    /// Full data shared into a TEE (clean-room style).
    TeeSharedData,
}

// =============================================================================
// RoundContribution
// =============================================================================

/// Per-round contribution metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundContribution {
    /// Round id.
    pub round_id: String,
    /// RFC 3339 — round timestamp.
    pub at: String,
    /// Number of samples contributed.
    pub sample_count: u64,
    /// Gradient / update SHA-256 (immutable evidence).
    pub update_sha256: String,
    /// Aggregation weight assigned.
    pub weight: u64,
}

// =============================================================================
// ParticipantEvent
// =============================================================================

/// One event on the participant timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: ParticipantStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// FederatedParticipant
// =============================================================================

/// One federated participant record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FederatedParticipant {
    /// Unique participant id (e.g., "FED-PART-2025-007").
    pub participant_id: String,
    /// Tenant / orchestrator scope.
    pub tenant_id: String,
    /// Federation / cohort id this participant belongs to.
    pub federation_id: String,
    /// Legal entity name.
    pub legal_entity: String,
    /// Display name.
    pub display_name: String,
    /// Sponsoring contact on participant side.
    pub sponsor: String,
    /// Stage.
    pub stage: ParticipantStage,
    /// Consent scope.
    pub consent_scope: ConsentScope,
    /// Contribution mode.
    pub contribution_mode: ContributionMode,
    /// Linked DPA / consortium agreement id.
    pub agreement_id: Option<String>,
    /// Per-round contributions.
    pub contributions: Vec<RoundContribution>,
    /// RFC 3339 — invited.
    pub invited_at: String,
    /// RFC 3339 — enrolled (signed agreement).
    pub enrolled_at: Option<String>,
    /// RFC 3339 — first activated.
    pub activated_at: Option<String>,
    /// RFC 3339 — closed (terminal).
    pub closed_at: Option<String>,
    /// Free-text final outcome.
    pub final_summary: Option<String>,
    /// Event log.
    pub events: Vec<ParticipantEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl FederatedParticipant {
    /// New `Invited` participant.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        participant_id: impl Into<String>,
        tenant_id: impl Into<String>,
        federation_id: impl Into<String>,
        legal_entity: impl Into<String>,
        display_name: impl Into<String>,
        sponsor: impl Into<String>,
        consent_scope: ConsentScope,
        contribution_mode: ContributionMode,
        invited_at: impl Into<String>,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            tenant_id: tenant_id.into(),
            federation_id: federation_id.into(),
            legal_entity: legal_entity.into(),
            display_name: display_name.into(),
            sponsor: sponsor.into(),
            stage: ParticipantStage::Invited,
            consent_scope,
            contribution_mode,
            agreement_id: None,
            contributions: Vec::new(),
            invited_at: invited_at.into(),
            enrolled_at: None,
            activated_at: None,
            closed_at: None,
            final_summary: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Total samples contributed across all rounds.
    pub fn total_samples(&self) -> u64 {
        self.contributions.iter().map(|c| c.sample_count).sum()
    }

    /// Total weight contributed.
    pub fn total_weight(&self) -> u64 {
        self.contributions.iter().map(|c| c.weight).sum()
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: ParticipantStage, to: ParticipantStage) -> bool {
    use ParticipantStage::*;
    matches!(
        (from, to),
        (Invited, Enrolled)
            | (Invited, Withdrawn)
            | (Invited, Terminated)
            | (Enrolled, Active)
            | (Enrolled, Withdrawn)
            | (Enrolled, Terminated)
            | (Active, Suspended)
            | (Active, Withdrawn)
            | (Active, Terminated)
            | (Suspended, Active)
            | (Suspended, Withdrawn)
            | (Suspended, Terminated)
    )
}

// =============================================================================
// FederatedParticipantRegister
// =============================================================================

/// Thread-safe register of federated participants.
#[derive(Debug, Default)]
pub struct FederatedParticipantRegister {
    inner: RwLock<HashMap<String, FederatedParticipant>>,
}

impl FederatedParticipantRegister {
    /// New empty register.
    pub fn new() -> Self {
        Self::default()
    }

    /// Invite a participant.
    pub fn invite(&self, participant: FederatedParticipant) -> SandboxResult<()> {
        if !matches!(participant.stage, ParticipantStage::Invited) {
            return Err(SandboxError::Other(format!(
                "participant must start Invited, got {:?}",
                participant.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        if g.contains_key(&participant.participant_id) {
            return Err(SandboxError::Other(format!(
                "participant already invited: {}",
                participant.participant_id
            )));
        }
        g.insert(participant.participant_id.clone(), participant);
        Ok(())
    }

    /// Mark Enrolled (signed agreement).
    pub fn enroll(
        &self,
        participant_id: &str,
        agreement_id: impl Into<String>,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        let p = g
            .get_mut(participant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown participant {participant_id}")))?;
        if !legal_transition(p.stage, ParticipantStage::Enrolled) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Enrolled",
                p.stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        p.stage = ParticipantStage::Enrolled;
        p.enrolled_at = Some(when.clone());
        p.agreement_id = Some(agreement_id.into());
        p.events.push(ParticipantEvent {
            at: when,
            actor,
            stage: ParticipantStage::Enrolled,
            note: "agreement signed".into(),
        });
        Ok(p.clone())
    }

    /// Activate (Enrolled or Suspended → Active).
    pub fn activate(
        &self,
        participant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        let p = g
            .get_mut(participant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown participant {participant_id}")))?;
        if !legal_transition(p.stage, ParticipantStage::Active) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Active",
                p.stage
            )));
        }
        let when = at.into();
        p.stage = ParticipantStage::Active;
        if p.activated_at.is_none() {
            p.activated_at = Some(when.clone());
        }
        p.events.push(ParticipantEvent {
            at: when,
            actor: actor.into(),
            stage: ParticipantStage::Active,
            note: "activated".into(),
        });
        Ok(p.clone())
    }

    /// Suspend.
    pub fn suspend(
        &self,
        participant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        self.simple_transition(
            participant_id,
            ParticipantStage::Suspended,
            actor,
            at,
            reason,
        )
    }

    /// Withdraw (participant-driven).
    pub fn withdraw(
        &self,
        participant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        self.simple_transition(
            participant_id,
            ParticipantStage::Withdrawn,
            actor,
            at,
            reason,
        )
    }

    /// Terminate (orchestrator-driven).
    pub fn terminate(
        &self,
        participant_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
        reason: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        self.simple_transition(
            participant_id,
            ParticipantStage::Terminated,
            actor,
            at,
            reason,
        )
    }

    fn simple_transition(
        &self,
        participant_id: &str,
        new_stage: ParticipantStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<FederatedParticipant> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        let p = g
            .get_mut(participant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown participant {participant_id}")))?;
        if !legal_transition(p.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                p.stage, new_stage
            )));
        }
        let when = at.into();
        let note = note.into();
        p.stage = new_stage;
        if new_stage.is_terminal() {
            p.closed_at = Some(when.clone());
            p.final_summary = Some(note.clone());
        }
        p.events.push(ParticipantEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note,
        });
        Ok(p.clone())
    }

    /// Record a per-round contribution. Allowed only when Active.
    pub fn record_contribution(
        &self,
        participant_id: &str,
        contribution: RoundContribution,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        let p = g
            .get_mut(participant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown participant {participant_id}")))?;
        if !p.stage.is_active() {
            return Err(SandboxError::Other(format!(
                "cannot record contribution on {participant_id}: stage is {:?}",
                p.stage
            )));
        }
        if p.contributions
            .iter()
            .any(|c| c.round_id == contribution.round_id)
        {
            return Err(SandboxError::Other(format!(
                "contribution for round already recorded: {}",
                contribution.round_id
            )));
        }
        p.contributions.push(contribution);
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(
        &self,
        participant_id: &str,
        tag: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("federated participant register poisoned".into()))?;
        let p = g
            .get_mut(participant_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown participant {participant_id}")))?;
        let tag = tag.into();
        if !p.tags.contains(&tag) {
            p.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, participant_id: &str) -> Option<FederatedParticipant> {
        let g = self.inner.read().ok()?;
        g.get(participant_id).cloned()
    }

    /// All participants.
    pub fn all(&self) -> Vec<FederatedParticipant> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// For a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<FederatedParticipant> {
        self.all()
            .into_iter()
            .filter(|p| p.tenant_id == tenant_id)
            .collect()
    }

    /// For a federation.
    pub fn for_federation(&self, federation_id: &str) -> Vec<FederatedParticipant> {
        self.all()
            .into_iter()
            .filter(|p| p.federation_id == federation_id)
            .collect()
    }

    /// By stage.
    pub fn by_stage(&self, stage: ParticipantStage) -> Vec<FederatedParticipant> {
        self.all().into_iter().filter(|p| p.stage == stage).collect()
    }

    /// Currently active participants.
    pub fn active_participants(&self) -> Vec<FederatedParticipant> {
        self.by_stage(ParticipantStage::Active)
    }

    /// Total sample count summed across all participants in a federation.
    pub fn total_samples_for_federation(&self, federation_id: &str) -> u64 {
        self.for_federation(federation_id)
            .iter()
            .map(|p| p.total_samples())
            .sum()
    }

    /// Number of participants.
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

    fn participant(id: &str, federation: &str) -> FederatedParticipant {
        FederatedParticipant::new(
            id,
            "tenant-orch",
            federation,
            format!("Acme Hospital {id}"),
            format!("Display {id}"),
            "ciso@acme.test",
            ConsentScope::CohortStudy,
            ContributionMode::SecureAggregation,
            "2025-04-01T00:00:00Z",
        )
    }

    fn contribution(round: &str, samples: u64, weight: u64) -> RoundContribution {
        RoundContribution {
            round_id: round.into(),
            at: "2025-04-15T00:00:00Z".into(),
            sample_count: samples,
            update_sha256: "sha-update".into(),
            weight,
        }
    }

    #[test]
    fn invite_and_get() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        assert!(r.get("p1").is_some());
    }

    #[test]
    fn duplicate_invite_errors() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        let err = r.invite(participant("p1", "fed-1")).unwrap_err();
        assert!(format!("{err}").contains("already invited"));
    }

    #[test]
    fn must_start_invited() {
        let mut p = participant("p1", "fed-1");
        p.stage = ParticipantStage::Active;
        let r = FederatedParticipantRegister::new();
        let err = r.invite(p).unwrap_err();
        assert!(format!("{err}").contains("must start Invited"));
    }

    #[test]
    fn legal_transitions() {
        use ParticipantStage::*;
        assert!(legal_transition(Invited, Enrolled));
        assert!(legal_transition(Enrolled, Active));
        assert!(legal_transition(Active, Suspended));
        assert!(legal_transition(Suspended, Active));
        assert!(legal_transition(Active, Withdrawn));
        assert!(legal_transition(Active, Terminated));
        assert!(legal_transition(Suspended, Withdrawn));
        // illegal
        assert!(!legal_transition(Invited, Active));
        assert!(!legal_transition(Withdrawn, Active));
        assert!(!legal_transition(Terminated, Active));
    }

    #[test]
    fn happy_path_lifecycle() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.enroll("p1", "DPA-007", "compliance", "2025-04-05T00:00:00Z").unwrap();
        r.activate("p1", "orchestrator", "2025-04-10T00:00:00Z").unwrap();
        r.record_contribution("p1", contribution("round-1", 10_000, 100))
            .unwrap();
        r.record_contribution("p1", contribution("round-2", 12_000, 100))
            .unwrap();
        r.suspend("p1", "orchestrator", "2025-04-20T00:00:00Z", "audit pause")
            .unwrap();
        r.activate("p1", "orchestrator", "2025-04-22T00:00:00Z").unwrap();
        let p = r
            .withdraw("p1", "participant", "2025-04-30T00:00:00Z", "policy change")
            .unwrap();
        assert_eq!(p.stage, ParticipantStage::Withdrawn);
        assert!(p.stage.is_terminal());
        assert_eq!(p.total_samples(), 22_000);
        assert_eq!(p.contributions.len(), 2);
        assert_eq!(p.agreement_id.as_deref(), Some("DPA-007"));
    }

    #[test]
    fn record_contribution_only_when_active() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        let err = r
            .record_contribution("p1", contribution("round-1", 10_000, 100))
            .unwrap_err();
        assert!(format!("{err}").contains("cannot record contribution"));
    }

    #[test]
    fn record_contribution_dedupes_round() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.enroll("p1", "DPA-007", "x", "2025-04-05T00:00:00Z").unwrap();
        r.activate("p1", "orchestrator", "2025-04-10T00:00:00Z").unwrap();
        r.record_contribution("p1", contribution("round-1", 10_000, 100))
            .unwrap();
        let err = r
            .record_contribution("p1", contribution("round-1", 5_000, 50))
            .unwrap_err();
        assert!(format!("{err}").contains("already recorded"));
    }

    #[test]
    fn terminate_from_invited() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        let p = r
            .terminate("p1", "orchestrator", "2025-04-05T00:00:00Z", "policy violation")
            .unwrap();
        assert_eq!(p.stage, ParticipantStage::Terminated);
    }

    #[test]
    fn illegal_transition_errors() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        let err = r.activate("p1", "orchestrator", "2025-04-10T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn add_tag_dedupes() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.add_tag("p1", "hospital").unwrap();
        r.add_tag("p1", "hospital").unwrap();
        r.add_tag("p1", "regulated").unwrap();
        assert_eq!(r.get("p1").unwrap().tags, vec!["hospital", "regulated"]);
    }

    #[test]
    fn unknown_participant_errors() {
        let r = FederatedParticipantRegister::new();
        let err = r.activate("nope", "x", "2025-04-10T00:00:00Z").unwrap_err();
        assert!(format!("{err}").contains("unknown participant"));
    }

    #[test]
    fn for_tenant_for_federation_filters() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        let mut other = participant("p2", "fed-2");
        other.tenant_id = "tenant-other".into();
        r.invite(other).unwrap();
        assert_eq!(r.for_tenant("tenant-orch").len(), 1);
        assert_eq!(r.for_tenant("tenant-other").len(), 1);
        assert_eq!(r.for_federation("fed-1").len(), 1);
        assert_eq!(r.for_federation("fed-2").len(), 1);
    }

    #[test]
    fn by_stage_active_filters() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.invite(participant("p2", "fed-1")).unwrap();
        r.enroll("p1", "DPA-007", "x", "2025-04-05T00:00:00Z").unwrap();
        r.activate("p1", "orchestrator", "2025-04-10T00:00:00Z").unwrap();
        assert_eq!(r.by_stage(ParticipantStage::Invited).len(), 1);
        assert_eq!(r.active_participants().len(), 1);
    }

    #[test]
    fn total_samples_aggregation() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.invite(participant("p2", "fed-1")).unwrap();
        for id in ["p1", "p2"] {
            r.enroll(id, "DPA-007", "x", "2025-04-05T00:00:00Z").unwrap();
            r.activate(id, "orchestrator", "2025-04-10T00:00:00Z").unwrap();
            r.record_contribution(id, contribution("round-1", 5_000, 50)).unwrap();
        }
        assert_eq!(r.total_samples_for_federation("fed-1"), 10_000);
    }

    #[test]
    fn total_weight_helper() {
        let r = FederatedParticipantRegister::new();
        r.invite(participant("p1", "fed-1")).unwrap();
        r.enroll("p1", "DPA-007", "x", "2025-04-05T00:00:00Z").unwrap();
        r.activate("p1", "orchestrator", "2025-04-10T00:00:00Z").unwrap();
        r.record_contribution("p1", contribution("round-1", 5_000, 70)).unwrap();
        r.record_contribution("p1", contribution("round-2", 3_000, 30)).unwrap();
        assert_eq!(r.get("p1").unwrap().total_weight(), 100);
    }

    #[test]
    fn stage_helpers() {
        assert!(ParticipantStage::Active.is_active());
        assert!(!ParticipantStage::Suspended.is_active());
        for s in [ParticipantStage::Withdrawn, ParticipantStage::Terminated] {
            assert!(s.is_terminal());
        }
        for s in [
            ParticipantStage::Invited,
            ParticipantStage::Enrolled,
            ParticipantStage::Active,
            ParticipantStage::Suspended,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let r = FederatedParticipantRegister::new();
        assert_eq!(r.count(), 0);
        r.invite(participant("p1", "fed-1")).unwrap();
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn participant_serde() {
        let p = participant("p1", "fed-1");
        let j = serde_json::to_string(&p).unwrap();
        let back: FederatedParticipant = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn contribution_serde() {
        let c = contribution("round-1", 5_000, 100);
        let j = serde_json::to_string(&c).unwrap();
        let back: RoundContribution = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn enums_serde() {
        for s in [
            ParticipantStage::Invited,
            ParticipantStage::Enrolled,
            ParticipantStage::Active,
            ParticipantStage::Suspended,
            ParticipantStage::Withdrawn,
            ParticipantStage::Terminated,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<ParticipantStage>(&serde_json::to_string(&s).unwrap())
                    .unwrap()
            );
        }
        for c in [
            ConsentScope::SingleRound,
            ConsentScope::CohortStudy,
            ConsentScope::Continuous,
            ConsentScope::BenchOnly,
        ] {
            assert_eq!(
                c,
                serde_json::from_str::<ConsentScope>(&serde_json::to_string(&c).unwrap()).unwrap()
            );
        }
        for m in [
            ContributionMode::LocalTraining,
            ContributionMode::SecureAggregation,
            ContributionMode::DpLocal,
            ContributionMode::DpCentral,
            ContributionMode::TeeSharedData,
        ] {
            assert_eq!(
                m,
                serde_json::from_str::<ContributionMode>(&serde_json::to_string(&m).unwrap())
                    .unwrap()
            );
        }
    }
}
