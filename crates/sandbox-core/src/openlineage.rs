//! OpenLineage event emitter (spec v1.0.5).
//!
//! [OpenLineage](https://openlineage.io/) is the industry standard for
//! describing data lineage across tools — Marquez, Datakin, Astronomer
//! Observe, Atlan, Egeria all consume the same event format. By emitting
//! OpenLineage events for every seal, Aethelred plugs into existing
//! enterprise data-catalog stacks instead of asking customers to learn
//! a new shape.
//!
//! ## Event shape
//!
//! Each seal emits a `RunEvent` with:
//! - `eventType`: `START` / `RUNNING` / `COMPLETE` / `ABORT` / `FAIL`.
//! - `eventTime`: RFC 3339 UTC.
//! - `producer`: `https://aethelred.network/sandbox-core/{version}`.
//! - `run`: `{ runId: <seal_id>, facets: { aethelred_seal: {...} } }`.
//! - `job`: `{ namespace: <tenant>, name: <workflow_id>, facets: {} }`.
//! - `inputs` / `outputs`: dataset arrays referencing `policy_id`,
//!   `model.model_id`, etc.
//!
//! ## What this gives you
//!
//! Auditors with Marquez see a unified DAG:
//!
//!   `dataset:fab.credit.applications` → `job:credit_decision` →
//!   `dataset:fab.credit.decisions`  ← `model:credit_v3`
//!
//! ...with the seal's Merkle proof attached as a custom facet.

use crate::seal::DigitalSeal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// Wire format (OpenLineage v1.0.5)
// =============================================================================

/// `eventType` values per OpenLineage spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EventType {
    /// Run started.
    Start,
    /// Run is in progress.
    Running,
    /// Run completed successfully.
    Complete,
    /// Run was aborted.
    Abort,
    /// Run failed.
    Fail,
    /// Other / informational.
    Other,
}

/// One OpenLineage `RunEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunEvent {
    /// `START` / `COMPLETE` / `FAIL` etc.
    #[serde(rename = "eventType")]
    pub event_type: EventType,
    /// RFC 3339 timestamp.
    #[serde(rename = "eventTime")]
    pub event_time: String,
    /// Producer URI (Aethelred sandbox version).
    pub producer: String,
    /// Schema URL (must reference the OpenLineage JSON Schema).
    #[serde(rename = "schemaURL")]
    pub schema_url: String,
    /// Run object.
    pub run: Run,
    /// Job object.
    pub job: Job,
    /// Input datasets.
    #[serde(default)]
    pub inputs: Vec<Dataset>,
    /// Output datasets.
    #[serde(default)]
    pub outputs: Vec<Dataset>,
}

/// `Run` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    /// UUIDv7 — same as `seal_id`.
    #[serde(rename = "runId")]
    pub run_id: Uuid,
    /// Facets (extension points).
    #[serde(default)]
    pub facets: BTreeMap<String, serde_json::Value>,
}

/// `Job` block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    /// Tenant id.
    pub namespace: String,
    /// Workflow id.
    pub name: String,
    /// Facets.
    #[serde(default)]
    pub facets: BTreeMap<String, serde_json::Value>,
}

/// Dataset reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Tenant / source namespace.
    pub namespace: String,
    /// Dataset name (e.g., `policy:po_credit_v3`).
    pub name: String,
    /// Facets.
    #[serde(default)]
    pub facets: BTreeMap<String, serde_json::Value>,
}

// =============================================================================
// Builder
// =============================================================================

/// Build an OpenLineage event from an Aethelred seal.
pub fn from_seal(seal: &DigitalSeal, event_type: EventType) -> RunEvent {
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    // Aethelred custom facet — preserves seal-level evidence references.
    let mut run_facets = BTreeMap::new();
    run_facets.insert(
        "aethelred_seal".into(),
        serde_json::json!({
            "_producer": "https://aethelred.network",
            "_schemaURL": "https://aethelred.network/schemas/openlineage_seal_facet/v1.json",
            "seal_id": seal.seal_id,
            "schema_version": seal.schema_version,
            "policy_id": seal.policy_id,
            "input_hash": seal.input_hash.to_hex(),
            "output_hash": seal.output_hash.to_hex(),
            "event_hash": seal.event_hash.to_hex(),
            "model_hash": seal.model.model_hash.to_hex(),
            "model_id": seal.model.model_id,
            "jurisdiction_tag": seal.jurisdiction_tag,
            "retention": format!("{:?}", seal.retention),
            "approvals_count": seal.approvals.len(),
        }),
    );
    let run = Run {
        run_id: seal.seal_id,
        facets: run_facets,
    };
    let job_facets = BTreeMap::from([(
        "documentation".into(),
        serde_json::json!({
            "_producer": "https://aethelred.network",
            "_schemaURL": "https://openlineage.io/spec/facets/1-0-1/DocumentationJobFacet.json",
            "description": format!("Aethelred sealed AI event: sector={:?}, jurisdiction={}", seal.sector, seal.jurisdiction_tag),
        }),
    )]);
    let job = Job {
        namespace: seal.tenant_id.clone(),
        name: seal.workflow_id.clone(),
        facets: job_facets,
    };
    // Inputs: policy + model + (best-effort) input_hash dataset.
    let inputs = vec![
        Dataset {
            namespace: seal.tenant_id.clone(),
            name: format!("policy:{}", seal.policy_id),
            facets: BTreeMap::new(),
        },
        Dataset {
            namespace: seal.tenant_id.clone(),
            name: format!("model:{}", seal.model.model_id),
            facets: BTreeMap::from([(
                "version".into(),
                serde_json::json!({
                    "version": seal.model.model_version.clone().unwrap_or_default(),
                    "framework": seal.model.framework.clone().unwrap_or_default(),
                }),
            )]),
        },
    ];
    // Outputs: a dataset named after the event_type.
    let outputs = vec![Dataset {
        namespace: seal.tenant_id.clone(),
        name: format!("event:{}", seal.event_type),
        facets: BTreeMap::new(),
    }];

    RunEvent {
        event_type,
        event_time: now,
        producer: format!(
            "https://aethelred.network/sandbox-core/{}",
            env!("CARGO_PKG_VERSION")
        ),
        schema_url:
            "https://openlineage.io/spec/1-0-5/OpenLineage.json#/$defs/RunEvent"
                .into(),
        run,
        job,
        inputs,
        outputs,
    }
}

// =============================================================================
// Emitter
// =============================================================================

/// Pluggable emitter contract.
pub trait OpenLineageEmitter: Send + Sync {
    /// Emit one event.
    fn emit(&self, event: &RunEvent) -> crate::SandboxResult<()>;
}

/// In-memory emitter for tests / dev.
#[derive(Debug, Default)]
pub struct InMemoryEmitter {
    events: std::sync::Mutex<Vec<RunEvent>>,
}

impl InMemoryEmitter {
    /// New emitter.
    pub fn new() -> Self {
        Self::default()
    }
    /// All emitted events.
    pub fn events(&self) -> Vec<RunEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }
    /// Number of events emitted.
    pub fn count(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }
}

impl OpenLineageEmitter for InMemoryEmitter {
    fn emit(&self, event: &RunEvent) -> crate::SandboxResult<()> {
        match self.events.lock() {
            Ok(mut g) => g.push(event.clone()),
            Err(e) => e.into_inner().push(event.clone()),
        }
        Ok(())
    }
}

/// File emitter — appends events as JSON-lines to a file (Marquez can
/// `tail -f` this and ingest).
pub struct FileEmitter {
    path: std::path::PathBuf,
}

impl FileEmitter {
    /// New emitter targeting `path`.
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
    /// Path of the underlying file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl OpenLineageEmitter for FileEmitter {
    fn emit(&self, event: &RunEvent) -> crate::SandboxResult<()> {
        use std::io::Write;
        let line = serde_json::to_string(event).map_err(|e| {
            crate::SandboxError::Other(format!("serialise event: {e}"))
        })?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| crate::SandboxError::Other(format!("open: {e}")))?;
        f.write_all(line.as_bytes())
            .map_err(|e| crate::SandboxError::Other(format!("write: {e}")))?;
        f.write_all(b"\n")
            .map_err(|e| crate::SandboxError::Other(format!("write nl: {e}")))?;
        f.sync_all()
            .map_err(|e| crate::SandboxError::Other(format!("sync: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::*;
    use crate::Sector;
    use std::collections::BTreeMap as StdBTreeMap;

    fn dummy_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision.approved".into(),
            event_hash: crate::Hasher::sha256(b"e"),
            model: ModelReference::new("credit_v3", crate::Hasher::sha256(b"w")),
            policy_id: "po_credit_v3".into(),
            input_hash: crate::Hasher::sha256(b"i"),
            output_hash: crate::Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: StdBTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn from_seal_produces_complete_event() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert_eq!(e.event_type, EventType::Complete);
        assert!(e.producer.contains("aethelred.network"));
        assert!(e.schema_url.contains("openlineage.io"));
    }

    #[test]
    fn from_seal_run_id_matches_seal_id() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert_eq!(e.run.run_id, s.seal_id);
    }

    #[test]
    fn from_seal_aethelred_facet_has_seal_id() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        let facet = e.run.facets.get("aethelred_seal").unwrap();
        assert_eq!(
            facet.get("seal_id").and_then(|v| v.as_str()),
            Some(s.seal_id.to_string().as_str())
        );
    }

    #[test]
    fn from_seal_job_namespace_is_tenant() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert_eq!(e.job.namespace, "FAB");
        assert_eq!(e.job.name, "credit_decision");
    }

    #[test]
    fn from_seal_inputs_include_policy_and_model() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        let names: Vec<&str> = e.inputs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.iter().any(|n| n.starts_with("policy:")));
        assert!(names.iter().any(|n| n.starts_with("model:")));
    }

    #[test]
    fn from_seal_outputs_include_event_dataset() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert!(e.outputs.iter().any(|d| d.name.starts_with("event:")));
    }

    #[test]
    fn event_serde_round_trip() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        let j = serde_json::to_string(&e).unwrap();
        let p: RunEvent = serde_json::from_str(&j).unwrap();
        assert_eq!(p.run.run_id, e.run.run_id);
    }

    #[test]
    fn event_type_serializes_uppercase() {
        let j = serde_json::to_string(&EventType::Complete).unwrap();
        assert_eq!(j, "\"COMPLETE\"");
    }

    #[test]
    fn in_memory_emitter_collects_events() {
        let em = InMemoryEmitter::new();
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Start);
        em.emit(&e).unwrap();
        em.emit(&e).unwrap();
        assert_eq!(em.count(), 2);
        assert_eq!(em.events().len(), 2);
    }

    #[test]
    fn file_emitter_appends() {
        let path = std::env::temp_dir().join(format!(
            "aethelred-ol-test-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let em = FileEmitter::new(&path);
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        em.emit(&e).unwrap();
        em.emit(&e).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_emitter_path_returned() {
        let path = std::env::temp_dir().join("foo.jsonl");
        let em = FileEmitter::new(&path);
        assert_eq!(em.path(), path.as_path());
    }

    #[test]
    fn event_types_serde_round_trip() {
        for et in [
            EventType::Start,
            EventType::Running,
            EventType::Complete,
            EventType::Abort,
            EventType::Fail,
            EventType::Other,
        ] {
            let j = serde_json::to_string(&et).unwrap();
            let p: EventType = serde_json::from_str(&j).unwrap();
            assert_eq!(p, et);
        }
    }

    #[test]
    fn dataset_namespace_is_tenant() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        for d in &e.inputs {
            assert_eq!(d.namespace, s.tenant_id);
        }
        for d in &e.outputs {
            assert_eq!(d.namespace, s.tenant_id);
        }
    }

    #[test]
    fn many_emit_calls_aggregate() {
        let em = InMemoryEmitter::new();
        let s = dummy_seal();
        for et in [EventType::Start, EventType::Running, EventType::Complete] {
            em.emit(&from_seal(&s, et)).unwrap();
        }
        assert_eq!(em.count(), 3);
    }

    #[test]
    fn aethelred_facet_includes_input_output_hashes() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        let facet = e.run.facets.get("aethelred_seal").unwrap();
        assert!(facet.get("input_hash").is_some());
        assert!(facet.get("output_hash").is_some());
    }

    #[test]
    fn job_documentation_facet_present() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert!(e.job.facets.contains_key("documentation"));
    }

    #[test]
    fn event_time_is_rfc3339() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert!(e.event_time.contains("T"));
    }

    #[test]
    fn schema_url_points_to_openlineage_v1() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        assert!(e.schema_url.contains("1-0-5"));
    }

    #[test]
    fn run_event_roundtrips_through_pretty_json() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Complete);
        let pretty = serde_json::to_string_pretty(&e).unwrap();
        let p: RunEvent = serde_json::from_str(&pretty).unwrap();
        assert_eq!(p.event_type, e.event_type);
    }

    #[test]
    fn dataset_serde_round_trip() {
        let d = Dataset {
            namespace: "FAB".into(),
            name: "policy:x".into(),
            facets: BTreeMap::new(),
        };
        let j = serde_json::to_string(&d).unwrap();
        let p: Dataset = serde_json::from_str(&j).unwrap();
        assert_eq!(p.name, d.name);
    }

    #[test]
    fn aborted_event_emits_correctly() {
        let s = dummy_seal();
        let e = from_seal(&s, EventType::Abort);
        assert_eq!(e.event_type, EventType::Abort);
    }
}
