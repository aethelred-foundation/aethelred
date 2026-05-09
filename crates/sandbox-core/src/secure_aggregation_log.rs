//! Secure multi-party aggregation run log.
//!
//! Distinct from [`crate::training_run`] (single-party ML training run)
//! and [`crate::federated_participant_register`] (per-participant
//! enrolment), this is the **per-aggregation-round operational log**:
//! every run of secure-aggregation / multi-party computation has a
//! record here with the protocol used, participating parties' update
//! hashes, the resulting aggregated output hash, and any abort or
//! disqualification events.
//!
//! Maps to the Confidential Computing Consortium's federation
//! guidance, the Google secure-aggregation paper (Bonawitz et al.),
//! and the broader MPC literature. Pairs with [`crate::differential_privacy`]
//! to give the auditor a chain of custody for each aggregation round.
//!
//! ## Lifecycle
//!
//! `Pending → Receiving → Aggregating → Completed | Aborted`
//!
//! `Receiving`: collecting masked updates from participants.
//! `Aggregating`: running the protocol's secure-sum / federated-average
//! step. `Completed`: aggregate produced; `Aborted`: protocol failed
//! (insufficient participants, integrity check failed, etc.).

use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// AggregationProtocol
// =============================================================================

/// Aggregation protocol used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationProtocol {
    /// Plain federated average (FedAvg).
    FedAvg,
    /// Secure-aggregation (Bonawitz et al.).
    SecureAgg,
    /// Homomorphic-encryption based.
    Homomorphic,
    /// Threshold-secret-sharing (Shamir).
    ThresholdSecretSharing,
    /// Trusted-execution-environment based.
    Tee,
    /// Differential-privacy aggregation.
    DpAggregation,
    /// Custom protocol.
    Custom,
}

impl AggregationProtocol {
    /// True if the protocol provides cryptographic guarantees against the
    /// aggregator learning individual updates.
    pub fn is_cryptographically_private(self) -> bool {
        matches!(
            self,
            Self::SecureAgg | Self::Homomorphic | Self::ThresholdSecretSharing | Self::Tee
        )
    }
}

// =============================================================================
// RoundStage
// =============================================================================

/// Lifecycle stage of an aggregation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStage {
    /// Round opened; not yet receiving updates.
    Pending,
    /// Collecting masked updates.
    Receiving,
    /// Running the secure-aggregation step.
    Aggregating,
    /// Aggregate produced.
    Completed,
    /// Round aborted (insufficient participants, integrity failure).
    Aborted,
}

impl RoundStage {
    /// True if no further state changes expected.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }
}

// =============================================================================
// AbortReason
// =============================================================================

/// Reason an aggregation round was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    /// Fewer participants than minimum (k-anonymity guard).
    InsufficientParticipants,
    /// One or more updates failed the integrity check.
    IntegrityFailure,
    /// Time exceeded.
    Timeout,
    /// Operator cancelled.
    OperatorCancel,
    /// Crypto / TEE attestation failed.
    AttestationFailure,
}

// =============================================================================
// ParticipantUpdate
// =============================================================================

/// One participant's contribution to a round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantUpdate {
    /// Participant id (matches
    /// [`crate::federated_participant_register::FederatedParticipant`]).
    pub participant_id: String,
    /// SHA-256 of the masked update (immutable evidence).
    pub update_sha256: String,
    /// Sample-count weight.
    pub weight: u64,
    /// True if the integrity check passed (commitment / MAC verified).
    pub integrity_ok: bool,
    /// True if the participant was disqualified for this round.
    pub disqualified: bool,
    /// RFC 3339 — when received.
    pub received_at: String,
}

// =============================================================================
// RoundEvent
// =============================================================================

/// One event on the round timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoundEvent {
    /// RFC 3339.
    pub at: String,
    /// Actor.
    pub actor: String,
    /// Stage applied.
    pub stage: RoundStage,
    /// Free-text note.
    pub note: String,
}

// =============================================================================
// AggregationRound
// =============================================================================

/// One aggregation-round record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregationRound {
    /// Unique round id.
    pub round_id: String,
    /// Tenant / orchestrator scope.
    pub tenant_id: String,
    /// Federation id this round belongs to.
    pub federation_id: String,
    /// Round number within the federation (monotonic).
    pub round_number: u64,
    /// Protocol used.
    pub protocol: AggregationProtocol,
    /// Stage.
    pub stage: RoundStage,
    /// Minimum number of valid participants required for the round to
    /// complete (k-anonymity / drop-out resilience guard).
    pub min_participants: u32,
    /// Updates received this round.
    pub updates: Vec<ParticipantUpdate>,
    /// SHA-256 of the resulting aggregate (set on Completed).
    pub aggregate_sha256: Option<String>,
    /// Abort reason (set on Aborted).
    pub abort_reason: Option<AbortReason>,
    /// Optional linked DP-budget entry id (privacy_budget_tracker).
    pub linked_dp_budget_id: Option<String>,
    /// RFC 3339 — opened.
    pub opened_at: String,
    /// RFC 3339 — closed (terminal).
    pub closed_at: Option<String>,
    /// Event log.
    pub events: Vec<RoundEvent>,
    /// Free-form tags.
    pub tags: Vec<String>,
}

impl AggregationRound {
    /// New `Pending` round.
    pub fn new(
        round_id: impl Into<String>,
        tenant_id: impl Into<String>,
        federation_id: impl Into<String>,
        round_number: u64,
        protocol: AggregationProtocol,
        min_participants: u32,
        opened_at: impl Into<String>,
    ) -> Self {
        Self {
            round_id: round_id.into(),
            tenant_id: tenant_id.into(),
            federation_id: federation_id.into(),
            round_number,
            protocol,
            stage: RoundStage::Pending,
            min_participants,
            updates: Vec::new(),
            aggregate_sha256: None,
            abort_reason: None,
            linked_dp_budget_id: None,
            opened_at: opened_at.into(),
            closed_at: None,
            events: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Number of updates passing integrity and not disqualified.
    pub fn valid_update_count(&self) -> usize {
        self.updates
            .iter()
            .filter(|u| u.integrity_ok && !u.disqualified)
            .count()
    }

    /// Total weight of valid updates.
    pub fn valid_total_weight(&self) -> u64 {
        self.updates
            .iter()
            .filter(|u| u.integrity_ok && !u.disqualified)
            .map(|u| u.weight)
            .sum()
    }

    /// True if at least `min_participants` valid updates have been received.
    pub fn meets_minimum(&self) -> bool {
        self.valid_update_count() >= self.min_participants as usize
    }
}

// =============================================================================
// Lifecycle transition table
// =============================================================================

fn legal_transition(from: RoundStage, to: RoundStage) -> bool {
    use RoundStage::*;
    matches!(
        (from, to),
        (Pending, Receiving)
            | (Pending, Aborted)
            | (Receiving, Aggregating)
            | (Receiving, Aborted)
            | (Aggregating, Completed)
            | (Aggregating, Aborted)
    )
}

// =============================================================================
// SecureAggregationLog
// =============================================================================

/// Thread-safe log of secure-aggregation rounds.
#[derive(Debug, Default)]
pub struct SecureAggregationLog {
    inner: RwLock<HashMap<String, AggregationRound>>,
}

impl SecureAggregationLog {
    /// New empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a new round.
    pub fn open(&self, round: AggregationRound) -> SandboxResult<()> {
        if !matches!(round.stage, RoundStage::Pending) {
            return Err(SandboxError::Other(format!(
                "round must start Pending, got {:?}",
                round.stage
            )));
        }
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        if g.contains_key(&round.round_id) {
            return Err(SandboxError::Other(format!(
                "round already opened: {}",
                round.round_id
            )));
        }
        g.insert(round.round_id.clone(), round);
        Ok(())
    }

    /// Move to Receiving.
    pub fn begin_receiving(
        &self,
        round_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AggregationRound> {
        self.simple_transition(round_id, RoundStage::Receiving, actor, at, "receiving updates")
    }

    /// Record a participant update. Allowed only in Receiving.
    pub fn record_update(
        &self,
        round_id: &str,
        update: ParticipantUpdate,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        if !matches!(r.stage, RoundStage::Receiving) {
            return Err(SandboxError::Other(format!(
                "cannot record update on {round_id}: stage is {:?}",
                r.stage
            )));
        }
        if r.updates
            .iter()
            .any(|u| u.participant_id == update.participant_id)
        {
            return Err(SandboxError::Other(format!(
                "update from participant already recorded: {}",
                update.participant_id
            )));
        }
        r.updates.push(update);
        Ok(())
    }

    /// Disqualify a participant's update post-hoc.
    pub fn disqualify(&self, round_id: &str, participant_id: &str) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        if !matches!(r.stage, RoundStage::Receiving | RoundStage::Aggregating) {
            return Err(SandboxError::Other(format!(
                "cannot disqualify on {round_id}: stage is {:?}",
                r.stage
            )));
        }
        let u = r
            .updates
            .iter_mut()
            .find(|u| u.participant_id == participant_id)
            .ok_or_else(|| {
                SandboxError::Other(format!("unknown participant update {participant_id}"))
            })?;
        u.disqualified = true;
        Ok(())
    }

    /// Begin Aggregating (Receiving → Aggregating).
    pub fn begin_aggregating(
        &self,
        round_id: &str,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AggregationRound> {
        self.simple_transition(
            round_id,
            RoundStage::Aggregating,
            actor,
            at,
            "aggregating",
        )
    }

    /// Complete the round with the aggregate hash. Errors if minimum
    /// participants threshold isn't met.
    pub fn complete(
        &self,
        round_id: &str,
        aggregate_sha256: impl Into<String>,
        actor: impl Into<String>,
        at: impl Into<String>,
    ) -> SandboxResult<AggregationRound> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        if !legal_transition(r.stage, RoundStage::Completed) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Completed",
                r.stage
            )));
        }
        if !r.meets_minimum() {
            return Err(SandboxError::Other(format!(
                "cannot complete {round_id}: only {} valid updates (min {})",
                r.valid_update_count(),
                r.min_participants
            )));
        }
        let when = at.into();
        let actor = actor.into();
        r.stage = RoundStage::Completed;
        r.aggregate_sha256 = Some(aggregate_sha256.into());
        r.closed_at = Some(when.clone());
        r.events.push(RoundEvent {
            at: when,
            actor,
            stage: RoundStage::Completed,
            note: "aggregation complete".into(),
        });
        Ok(r.clone())
    }

    /// Abort the round.
    pub fn abort(
        &self,
        round_id: &str,
        reason: AbortReason,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<AggregationRound> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        if !legal_transition(r.stage, RoundStage::Aborted) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> Aborted",
                r.stage
            )));
        }
        let when = at.into();
        let actor = actor.into();
        let note = note.into();
        r.stage = RoundStage::Aborted;
        r.abort_reason = Some(reason);
        r.closed_at = Some(when.clone());
        r.events.push(RoundEvent {
            at: when,
            actor,
            stage: RoundStage::Aborted,
            note,
        });
        Ok(r.clone())
    }

    fn simple_transition(
        &self,
        round_id: &str,
        new_stage: RoundStage,
        actor: impl Into<String>,
        at: impl Into<String>,
        note: impl Into<String>,
    ) -> SandboxResult<AggregationRound> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        if !legal_transition(r.stage, new_stage) {
            return Err(SandboxError::Other(format!(
                "illegal transition {:?} -> {:?}",
                r.stage, new_stage
            )));
        }
        let when = at.into();
        r.stage = new_stage;
        r.events.push(RoundEvent {
            at: when,
            actor: actor.into(),
            stage: new_stage,
            note: note.into(),
        });
        Ok(r.clone())
    }

    /// Link a DP budget entry id.
    pub fn link_dp_budget(
        &self,
        round_id: &str,
        budget_id: impl Into<String>,
    ) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        r.linked_dp_budget_id = Some(budget_id.into());
        Ok(())
    }

    /// Add a tag (deduplicated).
    pub fn add_tag(&self, round_id: &str, tag: impl Into<String>) -> SandboxResult<()> {
        let mut g = self
            .inner
            .write()
            .map_err(|_| SandboxError::Other("aggregation log poisoned".into()))?;
        let r = g
            .get_mut(round_id)
            .ok_or_else(|| SandboxError::Other(format!("unknown round {round_id}")))?;
        let tag = tag.into();
        if !r.tags.contains(&tag) {
            r.tags.push(tag);
        }
        Ok(())
    }

    /// Look up.
    pub fn get(&self, round_id: &str) -> Option<AggregationRound> {
        let g = self.inner.read().ok()?;
        g.get(round_id).cloned()
    }

    /// All rounds.
    pub fn all(&self) -> Vec<AggregationRound> {
        match self.inner.read() {
            Ok(g) => g.values().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Rounds for a tenant.
    pub fn for_tenant(&self, tenant_id: &str) -> Vec<AggregationRound> {
        self.all()
            .into_iter()
            .filter(|r| r.tenant_id == tenant_id)
            .collect()
    }

    /// Rounds for a federation.
    pub fn for_federation(&self, federation_id: &str) -> Vec<AggregationRound> {
        self.all()
            .into_iter()
            .filter(|r| r.federation_id == federation_id)
            .collect()
    }

    /// Rounds by stage.
    pub fn by_stage(&self, stage: RoundStage) -> Vec<AggregationRound> {
        self.all().into_iter().filter(|r| r.stage == stage).collect()
    }

    /// Aborted rounds for a federation.
    pub fn aborted_for_federation(&self, federation_id: &str) -> Vec<AggregationRound> {
        self.for_federation(federation_id)
            .into_iter()
            .filter(|r| matches!(r.stage, RoundStage::Aborted))
            .collect()
    }

    /// Number of registered rounds.
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

    fn round(id: &str, federation: &str, min: u32) -> AggregationRound {
        AggregationRound::new(
            id,
            "tenant-orch",
            federation,
            1,
            AggregationProtocol::SecureAgg,
            min,
            "2025-04-15T00:00:00Z",
        )
    }

    fn upd(participant: &str, ok: bool, weight: u64) -> ParticipantUpdate {
        ParticipantUpdate {
            participant_id: participant.into(),
            update_sha256: format!("sha-{participant}"),
            weight,
            integrity_ok: ok,
            disqualified: false,
            received_at: "2025-04-15T00:01:00Z".into(),
        }
    }

    #[test]
    fn open_and_get() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        assert!(l.get("r1").is_some());
    }

    #[test]
    fn duplicate_open_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        let err = l.open(round("r1", "fed-1", 3)).unwrap_err();
        assert!(format!("{err}").contains("already opened"));
    }

    #[test]
    fn must_start_pending() {
        let mut r = round("r1", "fed-1", 3);
        r.stage = RoundStage::Receiving;
        let l = SecureAggregationLog::new();
        let err = l.open(r).unwrap_err();
        assert!(format!("{err}").contains("must start Pending"));
    }

    #[test]
    fn legal_transitions() {
        use RoundStage::*;
        assert!(legal_transition(Pending, Receiving));
        assert!(legal_transition(Pending, Aborted));
        assert!(legal_transition(Receiving, Aggregating));
        assert!(legal_transition(Receiving, Aborted));
        assert!(legal_transition(Aggregating, Completed));
        assert!(legal_transition(Aggregating, Aborted));
        // illegal
        assert!(!legal_transition(Pending, Aggregating));
        assert!(!legal_transition(Completed, Aborted));
        assert!(!legal_transition(Aborted, Completed));
    }

    #[test]
    fn happy_path_lifecycle() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 10)).unwrap();
        l.record_update("r1", upd("p2", true, 20)).unwrap();
        l.record_update("r1", upd("p3", true, 30)).unwrap();
        l.begin_aggregating("r1", "orch", "2025-04-15T00:05:00Z").unwrap();
        let r = l
            .complete("r1", "sha-aggregate", "orch", "2025-04-15T00:06:00Z")
            .unwrap();
        assert_eq!(r.stage, RoundStage::Completed);
        assert_eq!(r.aggregate_sha256.as_deref(), Some("sha-aggregate"));
        assert_eq!(r.valid_update_count(), 3);
        assert_eq!(r.valid_total_weight(), 60);
        assert!(r.meets_minimum());
    }

    #[test]
    fn complete_below_minimum_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 10)).unwrap();
        l.record_update("r1", upd("p2", true, 20)).unwrap();
        l.begin_aggregating("r1", "orch", "2025-04-15T00:05:00Z").unwrap();
        let err = l
            .complete("r1", "sha", "orch", "2025-04-15T00:06:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("only 2 valid updates"));
    }

    #[test]
    fn integrity_failure_excludes_from_minimum() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 10)).unwrap();
        l.record_update("r1", upd("p2", true, 20)).unwrap();
        // p3 fails integrity
        l.record_update("r1", upd("p3", false, 30)).unwrap();
        l.begin_aggregating("r1", "orch", "2025-04-15T00:05:00Z").unwrap();
        let err = l
            .complete("r1", "sha", "orch", "2025-04-15T00:06:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("only 2 valid updates"));
    }

    #[test]
    fn disqualify_excludes_from_minimum() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 10)).unwrap();
        l.record_update("r1", upd("p2", true, 20)).unwrap();
        l.record_update("r1", upd("p3", true, 30)).unwrap();
        l.disqualify("r1", "p3").unwrap();
        l.begin_aggregating("r1", "orch", "2025-04-15T00:05:00Z").unwrap();
        let err = l
            .complete("r1", "sha", "orch", "2025-04-15T00:06:00Z")
            .unwrap_err();
        assert!(format!("{err}").contains("only 2 valid updates"));
    }

    #[test]
    fn record_update_dedupes_by_participant() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 10)).unwrap();
        let err = l.record_update("r1", upd("p1", true, 20)).unwrap_err();
        assert!(format!("{err}").contains("already recorded"));
    }

    #[test]
    fn record_update_outside_receiving_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        let err = l.record_update("r1", upd("p1", true, 10)).unwrap_err();
        assert!(format!("{err}").contains("cannot record update"));
    }

    #[test]
    fn disqualify_outside_phases_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        let err = l.disqualify("r1", "p1").unwrap_err();
        assert!(format!("{err}").contains("cannot disqualify"));
    }

    #[test]
    fn disqualify_unknown_participant_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        let err = l.disqualify("r1", "ghost").unwrap_err();
        assert!(format!("{err}").contains("unknown participant"));
    }

    #[test]
    fn abort_from_any_non_terminal() {
        let l = SecureAggregationLog::new();
        // From Pending
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.abort(
            "r1",
            AbortReason::OperatorCancel,
            "orch",
            "2025-04-15T00:02:00Z",
            "n",
        )
        .unwrap();
        assert_eq!(l.get("r1").unwrap().stage, RoundStage::Aborted);
        // From Receiving
        l.open(round("r2", "fed-1", 3)).unwrap();
        l.begin_receiving("r2", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.abort(
            "r2",
            AbortReason::Timeout,
            "orch",
            "2025-04-15T00:02:00Z",
            "n",
        )
        .unwrap();
        // From Aggregating
        l.open(round("r3", "fed-1", 1)).unwrap();
        l.begin_receiving("r3", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r3", upd("p1", true, 1)).unwrap();
        l.begin_aggregating("r3", "orch", "2025-04-15T00:02:00Z").unwrap();
        l.abort(
            "r3",
            AbortReason::IntegrityFailure,
            "orch",
            "2025-04-15T00:03:00Z",
            "n",
        )
        .unwrap();
    }

    #[test]
    fn abort_terminal_errors() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 1)).unwrap();
        l.begin_receiving("r1", "orch", "2025-04-15T00:01:00Z").unwrap();
        l.record_update("r1", upd("p1", true, 1)).unwrap();
        l.begin_aggregating("r1", "orch", "2025-04-15T00:02:00Z").unwrap();
        l.complete("r1", "sha", "orch", "2025-04-15T00:03:00Z").unwrap();
        let err = l
            .abort(
                "r1",
                AbortReason::OperatorCancel,
                "orch",
                "2025-04-15T00:04:00Z",
                "n",
            )
            .unwrap_err();
        assert!(format!("{err}").contains("illegal transition"));
    }

    #[test]
    fn link_dp_budget_set_tag() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.link_dp_budget("r1", "DP-007").unwrap();
        l.add_tag("r1", "production").unwrap();
        l.add_tag("r1", "production").unwrap();
        let r = l.get("r1").unwrap();
        assert_eq!(r.linked_dp_budget_id.as_deref(), Some("DP-007"));
        assert_eq!(r.tags, vec!["production"]);
    }

    #[test]
    fn unknown_round_errors() {
        let l = SecureAggregationLog::new();
        let err = l.link_dp_budget("nope", "x").unwrap_err();
        assert!(format!("{err}").contains("unknown round"));
    }

    #[test]
    fn for_tenant_federation_filters() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        let mut other = round("r2", "fed-2", 3);
        other.tenant_id = "tenant-other".into();
        l.open(other).unwrap();
        assert_eq!(l.for_tenant("tenant-orch").len(), 1);
        assert_eq!(l.for_tenant("tenant-other").len(), 1);
        assert_eq!(l.for_federation("fed-1").len(), 1);
        assert_eq!(l.for_federation("fed-2").len(), 1);
    }

    #[test]
    fn by_stage_aborted_filter() {
        let l = SecureAggregationLog::new();
        l.open(round("r1", "fed-1", 3)).unwrap();
        l.open(round("r2", "fed-1", 3)).unwrap();
        l.abort(
            "r2",
            AbortReason::Timeout,
            "orch",
            "2025-04-15T00:02:00Z",
            "n",
        )
        .unwrap();
        assert_eq!(l.by_stage(RoundStage::Pending).len(), 1);
        assert_eq!(l.aborted_for_federation("fed-1").len(), 1);
    }

    #[test]
    fn protocol_helpers() {
        assert!(AggregationProtocol::SecureAgg.is_cryptographically_private());
        assert!(AggregationProtocol::Homomorphic.is_cryptographically_private());
        assert!(AggregationProtocol::ThresholdSecretSharing.is_cryptographically_private());
        assert!(AggregationProtocol::Tee.is_cryptographically_private());
        assert!(!AggregationProtocol::FedAvg.is_cryptographically_private());
        assert!(!AggregationProtocol::DpAggregation.is_cryptographically_private());
    }

    #[test]
    fn stage_helpers() {
        for s in [RoundStage::Completed, RoundStage::Aborted] {
            assert!(s.is_terminal());
        }
        for s in [
            RoundStage::Pending,
            RoundStage::Receiving,
            RoundStage::Aggregating,
        ] {
            assert!(!s.is_terminal());
        }
    }

    #[test]
    fn count_tracks() {
        let l = SecureAggregationLog::new();
        assert_eq!(l.count(), 0);
        l.open(round("r1", "fed-1", 3)).unwrap();
        assert_eq!(l.count(), 1);
    }

    #[test]
    fn round_serde() {
        let r = round("r1", "fed-1", 3);
        let j = serde_json::to_string(&r).unwrap();
        let back: AggregationRound = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn enums_serde() {
        for p in [
            AggregationProtocol::FedAvg,
            AggregationProtocol::SecureAgg,
            AggregationProtocol::Homomorphic,
            AggregationProtocol::ThresholdSecretSharing,
            AggregationProtocol::Tee,
            AggregationProtocol::DpAggregation,
            AggregationProtocol::Custom,
        ] {
            assert_eq!(
                p,
                serde_json::from_str::<AggregationProtocol>(&serde_json::to_string(&p).unwrap())
                    .unwrap()
            );
        }
        for s in [
            RoundStage::Pending,
            RoundStage::Receiving,
            RoundStage::Aggregating,
            RoundStage::Completed,
            RoundStage::Aborted,
        ] {
            assert_eq!(
                s,
                serde_json::from_str::<RoundStage>(&serde_json::to_string(&s).unwrap()).unwrap()
            );
        }
        for r in [
            AbortReason::InsufficientParticipants,
            AbortReason::IntegrityFailure,
            AbortReason::Timeout,
            AbortReason::OperatorCancel,
            AbortReason::AttestationFailure,
        ] {
            assert_eq!(
                r,
                serde_json::from_str::<AbortReason>(&serde_json::to_string(&r).unwrap()).unwrap()
            );
        }
    }
}
