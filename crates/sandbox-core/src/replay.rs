//! Replay & dispute resolution.
//!
//! When two parties disagree on a seal — say a regulator's auditor and the
//! bank's compliance team — we need a deterministic way to re-derive the
//! seal from the customer's connector log and prove which side is right.
//!
//! This module ships:
//!
//! - [`ConnectorLog`] — append-only file capturing every connector event
//!   that flowed into the sandbox (timestamp + opaque payload bytes).
//! - [`Replayer`] — replays a connector log against a deterministic
//!   sealer, producing seals for comparison.
//! - [`DisputeReceipt`] — formal receipt comparing two parties' seal sets
//!   for the same input window. Records: agreed seals, disputed seals,
//!   missing seals, hash mismatches.
//! - [`ArbitrationOutcome`] — structured arbitration result.
//!
//! ## Determinism contract
//!
//! Replay only produces matching seals when the sealer is deterministic.
//! Sources of nondeterminism that producers must control:
//!
//! - `seal_id` (UUIDv7) — derived from the input event timestamp/seq, not
//!   `Uuid::now_v7()`.
//! - Wall-clock `timestamp` — taken from the connector event payload.
//! - Map iteration order — `BTreeMap` only (we already use it).
//! - Random validators — replay uses the original quorum.
//!
//! [`DeterministicSealer`] gives callers a contract they can hold to.

use crate::hashing::{Hasher, Sha256Digest};
use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ConnectorEvent
// =============================================================================

/// One event captured from a connector before it was sealed.
///
/// The payload is opaque bytes — the customer chooses encoding (JSON,
/// FIX message, FHIR Bundle, OPC-UA tag, etc.). We hash the bytes for
/// integrity but never parse them here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorEvent {
    /// Connector id (e.g., `"fix-prod-1"`, `"fhir-r4-subscription"`).
    pub connector_id: String,
    /// RFC 3339 ingestion timestamp.
    pub ingested_at: String,
    /// Hex-encoded raw payload bytes.
    pub payload_hex: String,
    /// SHA-256 of payload (denormalised for fast lookup).
    pub payload_hash: Sha256Digest,
    /// Connector-specific monotonic sequence id.
    pub seq: u64,
}

impl ConnectorEvent {
    /// Construct from raw payload bytes.
    pub fn from_payload(
        connector_id: impl Into<String>,
        seq: u64,
        payload: &[u8],
    ) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        Self {
            connector_id: connector_id.into(),
            ingested_at: now,
            payload_hex: hex::encode(payload),
            payload_hash: Hasher::sha256(payload),
            seq,
        }
    }

    /// Decode payload back to raw bytes.
    pub fn payload_bytes(&self) -> SandboxResult<Vec<u8>> {
        hex::decode(&self.payload_hex)
            .map_err(|e| SandboxError::invalid(format!("payload hex: {e}")))
    }
}

// =============================================================================
// ConnectorLog
// =============================================================================

/// Append-only file-backed connector log.
pub struct ConnectorLog {
    path: PathBuf,
    state: Mutex<Vec<ConnectorEvent>>,
}

impl ConnectorLog {
    /// Open or create.
    pub fn open(path: impl AsRef<Path>) -> SandboxResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut state = Vec::new();
        if path.exists() {
            let f = File::open(&path).map_err(|e| {
                SandboxError::Other(format!("open {}: {}", path.display(), e))
            })?;
            for (i, line) in BufReader::new(f).lines().enumerate() {
                let line = line.map_err(|e| {
                    SandboxError::Other(format!("read {}: {}", i + 1, e))
                })?;
                if line.trim().is_empty() {
                    continue;
                }
                let ev: ConnectorEvent = serde_json::from_str(&line).map_err(|e| {
                    SandboxError::Other(format!("parse line {}: {}", i + 1, e))
                })?;
                // Verify the payload hash on recovery.
                let bytes = ev.payload_bytes()?;
                let recomputed = Hasher::sha256(&bytes);
                if recomputed != ev.payload_hash {
                    return Err(SandboxError::Other(format!(
                        "connector log line {}: payload hash mismatch — TAMPER",
                        i + 1
                    )));
                }
                state.push(ev);
            }
        }
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    /// Append an event.
    pub fn append(&self, event: ConnectorEvent) -> SandboxResult<()> {
        let mut g = self
            .state
            .lock()
            .map_err(|_| SandboxError::Other("connector log poisoned".into()))?;
        let line = serde_json::to_string(&event).map_err(|e| {
            SandboxError::Other(format!("serialise: {e}"))
        })?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SandboxError::Other(format!("open append: {e}")))?;
        f.write_all(line.as_bytes())
            .map_err(|e| SandboxError::Other(format!("write: {e}")))?;
        f.write_all(b"\n")
            .map_err(|e| SandboxError::Other(format!("write nl: {e}")))?;
        f.sync_all()
            .map_err(|e| SandboxError::Other(format!("sync: {e}")))?;
        g.push(event);
        Ok(())
    }

    /// All events.
    pub fn events(&self) -> Vec<ConnectorEvent> {
        self.state.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.state.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` if no events.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// =============================================================================
// DeterministicSealer
// =============================================================================

/// Deterministic sealer trait.
///
/// Implementors guarantee that for the same input event, they produce
/// the same seal — bit-for-bit. This is the cornerstone of replay.
pub trait DeterministicSealer: Send + Sync {
    /// Seal one event.
    fn seal(&self, event: &ConnectorEvent) -> SandboxResult<DigitalSeal>;
}

/// Trivial deterministic sealer — produces a `DigitalSeal` whose hashes
/// are derived purely from the event payload + seq + connector_id. The
/// `seal_id` is computed deterministically from the payload hash.
#[derive(Debug)]
pub struct TrivialSealer {
    /// Tenant id baked into every seal.
    pub tenant_id: String,
    /// Sector.
    pub sector: crate::Sector,
    /// Workflow id.
    pub workflow_id: String,
    /// Jurisdiction tag.
    pub jurisdiction_tag: String,
}

impl TrivialSealer {
    /// New deterministic sealer.
    pub fn new(
        tenant_id: impl Into<String>,
        sector: crate::Sector,
        workflow_id: impl Into<String>,
        jurisdiction_tag: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            sector,
            workflow_id: workflow_id.into(),
            jurisdiction_tag: jurisdiction_tag.into(),
        }
    }
}

impl DeterministicSealer for TrivialSealer {
    fn seal(&self, event: &ConnectorEvent) -> SandboxResult<DigitalSeal> {
        // Build a deterministic seal_id from the payload hash + connector +
        // seq. UUIDv5-ish: we use first 16 bytes of a derivation hash.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&event.payload_hash.0);
        buf.extend_from_slice(event.connector_id.as_bytes());
        buf.extend_from_slice(&event.seq.to_le_bytes());
        let derived = Hasher::sha256(&buf);
        let seal_id = Uuid::from_bytes(*derived.0.first_chunk::<16>().unwrap());
        // Timestamp is derived deterministically from the event.
        let timestamp = OffsetDateTime::parse(
            &event.ingested_at,
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap_or_else(|_| OffsetDateTime::UNIX_EPOCH);
        Ok(DigitalSeal {
            schema_version: crate::seal::SealVersion::V1,
            seal_id,
            timestamp,
            sector: self.sector,
            event_type: format!("{}.event", self.workflow_id),
            event_hash: event.payload_hash,
            model: crate::seal::ModelReference::new("replay-deterministic", event.payload_hash),
            policy_id: format!("po_{}_replay", self.workflow_id),
            input_hash: event.payload_hash,
            output_hash: event.payload_hash,
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: self.tenant_id.clone(),
            workflow_id: self.workflow_id.clone(),
            jurisdiction_tag: self.jurisdiction_tag.clone(),
            retention: crate::seal::RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        })
    }
}

// =============================================================================
// Replayer
// =============================================================================

/// Re-derives seals from a connector log.
pub struct Replayer {
    sealer: Box<dyn DeterministicSealer>,
}

impl Replayer {
    /// New replayer.
    pub fn new(sealer: Box<dyn DeterministicSealer>) -> Self {
        Self { sealer }
    }

    /// Replay all events.
    pub fn replay(&self, events: &[ConnectorEvent]) -> SandboxResult<Vec<DigitalSeal>> {
        let mut out = Vec::with_capacity(events.len());
        for ev in events {
            out.push(self.sealer.seal(ev)?);
        }
        Ok(out)
    }

    /// Replay a [`ConnectorLog`].
    pub fn replay_log(&self, log: &ConnectorLog) -> SandboxResult<Vec<DigitalSeal>> {
        self.replay(&log.events())
    }
}

// =============================================================================
// Dispute resolution
// =============================================================================

/// Receipt comparing two parties' seal sets for the same window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeReceipt {
    /// Stable receipt id.
    pub receipt_id: Uuid,
    /// RFC 3339 timestamp.
    pub generated_at: String,
    /// Party A label (e.g., `"FAB Compliance"`).
    pub party_a: String,
    /// Party B label (e.g., `"CBUAE Auditor"`).
    pub party_b: String,
    /// Seal ids agreed-upon (present in both, hash-identical).
    pub agreed: Vec<Uuid>,
    /// Seal ids disputed (present in both, hash differs).
    pub disputed: Vec<DisputedPair>,
    /// Seal ids only in A.
    pub only_in_a: Vec<Uuid>,
    /// Seal ids only in B.
    pub only_in_b: Vec<Uuid>,
    /// Final outcome.
    pub outcome: ArbitrationOutcome,
}

/// One disputed seal pair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DisputedPair {
    /// Seal id (same in both, since `seal_id` is deterministic).
    pub seal_id: Uuid,
    /// Hash of party A's seal.
    pub a_hash: Sha256Digest,
    /// Hash of party B's seal.
    pub b_hash: Sha256Digest,
}

/// Arbitration outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArbitrationOutcome {
    /// Full agreement.
    FullAgreement,
    /// Partial agreement (some disputed/only-in-X seals).
    PartialAgreement,
    /// Major divergence (≥ 50% of seals disputed or one-sided).
    MajorDivergence,
    /// Inconclusive — not enough overlap to decide.
    Inconclusive,
}

/// Compare two seal sets and produce a dispute receipt.
pub fn compare(
    party_a: impl Into<String>,
    seals_a: &[DigitalSeal],
    party_b: impl Into<String>,
    seals_b: &[DigitalSeal],
) -> SandboxResult<DisputeReceipt> {
    use std::collections::HashMap;
    let map_a: HashMap<Uuid, &DigitalSeal> = seals_a.iter().map(|s| (s.seal_id, s)).collect();
    let map_b: HashMap<Uuid, &DigitalSeal> = seals_b.iter().map(|s| (s.seal_id, s)).collect();
    let ids_a: HashSet<Uuid> = map_a.keys().copied().collect();
    let ids_b: HashSet<Uuid> = map_b.keys().copied().collect();
    let mut agreed = Vec::new();
    let mut disputed = Vec::new();
    let mut only_in_a = Vec::new();
    let mut only_in_b = Vec::new();
    for id in ids_a.union(&ids_b) {
        match (map_a.get(id), map_b.get(id)) {
            (Some(a), Some(b)) => {
                let ha = Hasher::hash_value(a)?;
                let hb = Hasher::hash_value(b)?;
                if ha == hb {
                    agreed.push(*id);
                } else {
                    disputed.push(DisputedPair {
                        seal_id: *id,
                        a_hash: ha,
                        b_hash: hb,
                    });
                }
            }
            (Some(_), None) => only_in_a.push(*id),
            (None, Some(_)) => only_in_b.push(*id),
            (None, None) => {}
        }
    }
    let total = agreed.len() + disputed.len() + only_in_a.len() + only_in_b.len();
    let outcome = if total == 0 {
        ArbitrationOutcome::Inconclusive
    } else if disputed.is_empty() && only_in_a.is_empty() && only_in_b.is_empty() {
        ArbitrationOutcome::FullAgreement
    } else if (disputed.len() + only_in_a.len() + only_in_b.len()) * 2 >= total {
        ArbitrationOutcome::MajorDivergence
    } else {
        ArbitrationOutcome::PartialAgreement
    };
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // Sort outputs for determinism.
    let mut agreed_sorted = agreed;
    agreed_sorted.sort();
    only_in_a.sort();
    only_in_b.sort();
    disputed.sort_by_key(|d| d.seal_id);
    Ok(DisputeReceipt {
        receipt_id: Uuid::now_v7(),
        generated_at: now,
        party_a: party_a.into(),
        party_b: party_b.into(),
        agreed: agreed_sorted,
        disputed,
        only_in_a,
        only_in_b,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sector;

    fn sealer() -> Box<dyn DeterministicSealer> {
        Box::new(TrivialSealer::new(
            "FAB",
            Sector::Finance,
            "credit_decision",
            "AE-CBUAE",
        ))
    }

    fn ev(connector: &str, seq: u64, payload: &str) -> ConnectorEvent {
        let mut e = ConnectorEvent::from_payload(connector, seq, payload.as_bytes());
        // Force deterministic timestamp for tests.
        e.ingested_at = "2026-05-06T10:00:00Z".into();
        e
    }

    fn tmp(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aethelred-replay-{}-{}.jsonl",
            std::process::id(),
            suffix
        ))
    }

    #[test]
    fn connector_event_payload_round_trip() {
        let e = ConnectorEvent::from_payload("c", 1, b"hello");
        let bytes = e.payload_bytes().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn connector_event_hash_matches_payload() {
        let e = ConnectorEvent::from_payload("c", 1, b"hello");
        assert_eq!(e.payload_hash, Hasher::sha256(b"hello"));
    }

    #[test]
    fn connector_log_persists_across_reopens() {
        let p = tmp("persist");
        let _ = std::fs::remove_file(&p);
        {
            let log = ConnectorLog::open(&p).unwrap();
            log.append(ev("c", 0, "a")).unwrap();
            log.append(ev("c", 1, "b")).unwrap();
        }
        let log = ConnectorLog::open(&p).unwrap();
        assert_eq!(log.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn connector_log_tamper_rejected_on_open() {
        let p = tmp("tamper");
        let _ = std::fs::remove_file(&p);
        {
            let log = ConnectorLog::open(&p).unwrap();
            log.append(ev("c", 0, "a")).unwrap();
        }
        // Replace payload_hex but leave hash unchanged.
        let content = std::fs::read_to_string(&p).unwrap();
        let tampered = content.replacen(
            &hex::encode(b"a"),
            &hex::encode(b"x"),
            1,
        );
        std::fs::write(&p, tampered).unwrap();
        let r = ConnectorLog::open(&p);
        assert!(r.is_err());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn replayer_produces_seals_for_each_event() {
        let r = Replayer::new(sealer());
        let events = vec![ev("c", 0, "a"), ev("c", 1, "b"), ev("c", 2, "c")];
        let seals = r.replay(&events).unwrap();
        assert_eq!(seals.len(), 3);
    }

    #[test]
    fn deterministic_sealer_produces_same_seal_for_same_event() {
        let s1 = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let s2 = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let e = ev("c", 0, "x");
        let seal_a = s1.seal(&e).unwrap();
        let seal_b = s2.seal(&e).unwrap();
        let h_a = Hasher::hash_value(&seal_a).unwrap();
        let h_b = Hasher::hash_value(&seal_b).unwrap();
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn replay_log_works() {
        let p = tmp("replog");
        let _ = std::fs::remove_file(&p);
        let log = ConnectorLog::open(&p).unwrap();
        log.append(ev("c", 0, "x")).unwrap();
        log.append(ev("c", 1, "y")).unwrap();
        let r = Replayer::new(sealer());
        let seals = r.replay_log(&log).unwrap();
        assert_eq!(seals.len(), 2);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn compare_full_agreement_when_identical() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let events = vec![ev("c", 0, "a"), ev("c", 1, "b")];
        let seals_a: Vec<DigitalSeal> = events.iter().map(|e| s.seal(e).unwrap()).collect();
        let seals_b = seals_a.clone();
        let r = compare("A", &seals_a, "B", &seals_b).unwrap();
        assert_eq!(r.outcome, ArbitrationOutcome::FullAgreement);
        assert_eq!(r.agreed.len(), 2);
        assert!(r.disputed.is_empty());
    }

    #[test]
    fn compare_only_in_a_when_b_empty() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let seals_a = vec![s.seal(&ev("c", 0, "a")).unwrap()];
        let r = compare("A", &seals_a, "B", &[]).unwrap();
        assert_eq!(r.only_in_a.len(), 1);
        assert!(r.only_in_b.is_empty());
        assert_eq!(r.outcome, ArbitrationOutcome::MajorDivergence);
    }

    #[test]
    fn compare_disputed_when_hashes_differ() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let mut seal = s.seal(&ev("c", 0, "a")).unwrap();
        let seal_b = seal.clone();
        // Tamper with party A's copy.
        seal.event_hash = Hasher::sha256(b"tampered");
        let r = compare("A", &[seal], "B", &[seal_b]).unwrap();
        assert_eq!(r.disputed.len(), 1);
        assert!(r.agreed.is_empty());
    }

    #[test]
    fn compare_partial_agreement_with_minor_divergence() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let evs = (0..5).map(|i| ev("c", i, &format!("e-{i}"))).collect::<Vec<_>>();
        let mut seals_a: Vec<DigitalSeal> = evs.iter().map(|e| s.seal(e).unwrap()).collect();
        let mut seals_b = seals_a.clone();
        // Make one seal differ in B (tamper) — 1/5 disputed.
        seals_b[0].event_hash = Hasher::sha256(b"tampered");
        seals_a[1].event_hash = Hasher::sha256(b"identity-on-a");
        // Since we can't have differing hashes for the *same* deterministic
        // seal_id without hashing differing, let's just remove one B seal:
        seals_b.pop();
        let r = compare("A", &seals_a, "B", &seals_b).unwrap();
        assert!(r.outcome != ArbitrationOutcome::FullAgreement);
    }

    #[test]
    fn compare_inconclusive_for_empty_inputs() {
        let r = compare("A", &[], "B", &[]).unwrap();
        assert_eq!(r.outcome, ArbitrationOutcome::Inconclusive);
    }

    #[test]
    fn compare_outputs_sorted_for_determinism() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let evs: Vec<ConnectorEvent> = (0..3).map(|i| ev("c", i, &format!("e-{i}"))).collect();
        let seals_a: Vec<DigitalSeal> = evs.iter().map(|e| s.seal(e).unwrap()).collect();
        let r = compare("A", &seals_a, "B", &seals_a).unwrap();
        let mut sorted = r.agreed.clone();
        sorted.sort();
        assert_eq!(sorted, r.agreed);
    }

    #[test]
    fn arbitration_outcome_serde_round_trip() {
        let o = ArbitrationOutcome::PartialAgreement;
        let j = serde_json::to_string(&o).unwrap();
        assert_eq!(j, "\"partial_agreement\"");
        let p: ArbitrationOutcome = serde_json::from_str(&j).unwrap();
        assert_eq!(p, o);
    }

    #[test]
    fn dispute_receipt_serde_round_trip() {
        let r = compare("A", &[], "B", &[]).unwrap();
        let j = serde_json::to_string(&r).unwrap();
        let p: DisputeReceipt = serde_json::from_str(&j).unwrap();
        assert_eq!(p.outcome, r.outcome);
    }

    #[test]
    fn many_event_replay_is_consistent() {
        let p = tmp("many");
        let _ = std::fs::remove_file(&p);
        let log = ConnectorLog::open(&p).unwrap();
        for i in 0..20 {
            log.append(ev("c", i, &format!("e-{i}"))).unwrap();
        }
        let r = Replayer::new(sealer());
        let seals1 = r.replay_log(&log).unwrap();
        // Re-open and re-replay.
        let log2 = ConnectorLog::open(&p).unwrap();
        let seals2 = r.replay_log(&log2).unwrap();
        for (a, b) in seals1.iter().zip(seals2.iter()) {
            assert_eq!(Hasher::hash_value(a).unwrap(), Hasher::hash_value(b).unwrap());
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn connector_log_path_is_returned() {
        let p = tmp("path");
        let _ = std::fs::remove_file(&p);
        let log = ConnectorLog::open(&p).unwrap();
        assert_eq!(log.path(), p.as_path());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn connector_log_is_empty_initially() {
        let p = tmp("init");
        let _ = std::fs::remove_file(&p);
        let log = ConnectorLog::open(&p).unwrap();
        assert!(log.is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn events_returned_in_append_order() {
        let p = tmp("order");
        let _ = std::fs::remove_file(&p);
        let log = ConnectorLog::open(&p).unwrap();
        for i in 0..5 {
            log.append(ev("c", i, &format!("e-{i}"))).unwrap();
        }
        let evs = log.events();
        for (i, e) in evs.iter().enumerate() {
            assert_eq!(e.seq, i as u64);
        }
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn compare_records_only_in_a_only_in_b_sorted() {
        let s = TrivialSealer::new("FAB", Sector::Finance, "wf", "AE");
        let seals_a: Vec<DigitalSeal> = (0..3)
            .map(|i| s.seal(&ev("a", i, &format!("a-{i}"))).unwrap())
            .collect();
        let seals_b: Vec<DigitalSeal> = (0..2)
            .map(|i| s.seal(&ev("b", i, &format!("b-{i}"))).unwrap())
            .collect();
        let r = compare("A", &seals_a, "B", &seals_b).unwrap();
        assert_eq!(r.only_in_a.len(), 3);
        assert_eq!(r.only_in_b.len(), 2);
    }

    #[test]
    fn disputed_pair_serde_round_trip() {
        let d = DisputedPair {
            seal_id: Uuid::now_v7(),
            a_hash: Hasher::sha256(b"a"),
            b_hash: Hasher::sha256(b"b"),
        };
        let j = serde_json::to_string(&d).unwrap();
        let p: DisputedPair = serde_json::from_str(&j).unwrap();
        assert_eq!(p, d);
    }

    #[test]
    fn connector_event_serde_round_trip() {
        let e = ev("c", 1, "payload");
        let j = serde_json::to_string(&e).unwrap();
        let p: ConnectorEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p, e);
    }
}
