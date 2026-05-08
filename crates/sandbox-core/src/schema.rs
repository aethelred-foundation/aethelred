//! JSON-Schema export for [`crate::DigitalSeal`] and friends.
//!
//! Gated behind the `schema` feature so default builds stay slim. Enterprise
//! users opt in with:
//!
//! ```toml
//! aethelred-sandbox-core = { version = "0.2", features = ["schema"] }
//! ```
//!
//! ## What is exported
//!
//! - [`SchemaBundle::digital_seal_v1`] — the canonical AI-event evidence
//!   object schema, JSON Schema Draft 7.
//! - [`SchemaBundle::seal_envelope_v1`] — seal + Merkle proof + anchor.
//! - [`SchemaBundle::evidence_bundle_v1`] — exported audit bundle.
//!
//! ## Why hand-curated, not derive-generated
//!
//! Enterprise SDK teams (Java, .NET, TypeScript, Python) treat JSON schemas
//! as a stable contract. Macro-derived schemas can shift across `schemars`
//! versions; hand-curated schemas don't. This module is the source of truth.

use serde::{Deserialize, Serialize};

/// A JSON Schema bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaBundle {
    /// Schema for `DigitalSeal` (V1).
    pub digital_seal: serde_json::Value,
    /// Schema for `SealEnvelope` (V1).
    pub seal_envelope: serde_json::Value,
    /// Schema for `EvidenceBundle` (V1).
    pub evidence_bundle: serde_json::Value,
}

impl SchemaBundle {
    /// Generate the bundle (V1).
    pub fn generate() -> Self {
        Self {
            digital_seal: Self::digital_seal_v1(),
            seal_envelope: Self::seal_envelope_v1(),
            evidence_bundle: Self::evidence_bundle_v1(),
        }
    }

    /// Render the bundle as pretty JSON.
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("pretty json")
    }

    /// Hand-curated `DigitalSeal` v1 schema (Draft 7).
    pub fn digital_seal_v1() -> serde_json::Value {
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "https://aethelred.network/schemas/digital_seal/v1.json",
            "title": "DigitalSeal",
            "description": "Aethelred AI-event evidence object (V1).",
            "type": "object",
            "required": [
                "schema_version", "seal_id", "timestamp", "sector", "event_type",
                "event_hash", "model", "policy_id", "input_hash", "output_hash",
                "approvals", "tenant_id", "workflow_id", "jurisdiction_tag",
                "retention"
            ],
            "properties": {
                "schema_version": {
                    "type": "string",
                    "enum": ["v1"]
                },
                "seal_id": {
                    "type": "string",
                    "format": "uuid"
                },
                "timestamp": {
                    "type": "string",
                    "format": "date-time"
                },
                "sector": {
                    "type": "string",
                    "enum": ["finance", "healthcare", "defense", "supply_chain",
                             "ai_agents", "autonomous_mobility", "research"]
                },
                "event_type": { "type": "string" },
                "event_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "model": { "$ref": "#/definitions/ModelReference" },
                "policy_id": { "type": "string" },
                "input_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "output_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "approvals": {
                    "type": "array",
                    "items": { "$ref": "#/definitions/ApprovalRecord" }
                },
                "attestation": {
                    "oneOf": [
                        { "type": "null" },
                        { "$ref": "#/definitions/Attestation" }
                    ]
                },
                "zk_proof": {
                    "oneOf": [
                        { "type": "null" },
                        { "$ref": "#/definitions/ProofArtefact" }
                    ]
                },
                "tenant_id": { "type": "string", "minLength": 1 },
                "workflow_id": { "type": "string", "minLength": 1 },
                "jurisdiction_tag": { "type": "string" },
                "retention": {
                    "type": "string",
                    "enum": ["one_year", "five_years", "seven_years",
                             "ten_years", "twenty_five_years", "indefinite"]
                },
                "prior_seal_hash": {
                    "oneOf": [
                        { "type": "null" },
                        { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                    ]
                },
                "sector_extension": { "type": "object" },
                "validator_signature_hex": {
                    "oneOf": [
                        { "type": "null" },
                        { "type": "string", "pattern": "^[0-9a-fA-F]+$" }
                    ]
                }
            },
            "definitions": {
                "ModelReference": {
                    "type": "object",
                    "required": ["model_hash", "model_id"],
                    "properties": {
                        "model_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "model_id": { "type": "string" },
                        "model_version": { "oneOf": [ {"type": "null"}, {"type": "string"} ] },
                        "weights_commit_ref": { "oneOf": [ {"type": "null"}, {"type": "string"} ] },
                        "framework": { "oneOf": [ {"type": "null"}, {"type": "string"} ] },
                        "framework_version": { "oneOf": [ {"type": "null"}, {"type": "string"} ] },
                        "training_data_class": { "oneOf": [ {"type": "null"}, {"type": "string"} ] }
                    }
                },
                "ApprovalRecord": {
                    "type": "object",
                    "required": ["approver_ref", "role", "decision", "timestamp"],
                    "properties": {
                        "approver_ref": { "type": "string" },
                        "role": { "type": "string" },
                        "decision": { "type": "string" },
                        "reason_class": { "oneOf": [ {"type": "null"}, {"type": "string"} ] },
                        "timestamp": { "type": "string", "format": "date-time" },
                        "signature_hex": { "oneOf": [ {"type": "null"}, {"type": "string"} ] }
                    }
                },
                "Attestation": {
                    "type": "object",
                    "required": ["vendor", "attestation_doc_hash",
                                 "workload_measurement", "runtime_nonce", "verified"],
                    "properties": {
                        "vendor": {
                            "type": "object",
                            "required": ["platform", "root_ref"],
                            "properties": {
                                "platform": {
                                    "type": "string",
                                    "enum": ["intel_tdx", "amd_sev_snp", "aws_nitro",
                                             "nvidia_h100_cc", "arm_cca", "azure_cc",
                                             "gcp_confidential_space", "none"]
                                },
                                "root_ref": { "type": "string" },
                                "tcb_version": { "oneOf": [ {"type": "null"}, {"type": "string"} ] }
                            }
                        },
                        "attestation_doc_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "workload_measurement": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "runtime_nonce": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "verified": { "type": "boolean" },
                        "verifier_id": { "oneOf": [ {"type": "null"}, {"type": "string"} ] }
                    }
                },
                "ProofArtefact": {
                    "type": "object",
                    "required": ["system", "circuit_hash", "public_inputs_hash",
                                 "proof_blob_hash", "verifier_key_hash", "verified"],
                    "properties": {
                        "system": {
                            "type": "string",
                            "enum": ["ezkl", "risc_zero", "modulus_remainder",
                                     "plonky2", "groth16", "none"]
                        },
                        "circuit_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "public_inputs_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "proof_blob_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "verifier_key_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                        "verified": { "type": "boolean" }
                    }
                }
            }
        })
    }

    /// Hand-curated `SealEnvelope` v1 schema.
    pub fn seal_envelope_v1() -> serde_json::Value {
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "https://aethelred.network/schemas/seal_envelope/v1.json",
            "title": "SealEnvelope",
            "description": "DigitalSeal + optional Merkle inclusion proof + anchor height.",
            "type": "object",
            "required": ["seal"],
            "properties": {
                "seal": { "$ref": "https://aethelred.network/schemas/digital_seal/v1.json" },
                "merkle_proof": {
                    "oneOf": [
                        { "type": "null" },
                        {
                            "type": "object",
                            "required": ["leaf_index", "leaf_hash", "siblings", "root"],
                            "properties": {
                                "leaf_index": { "type": "integer", "minimum": 0 },
                                "leaf_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                                "siblings": {
                                    "type": "array",
                                    "items": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                                },
                                "root": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                            }
                        }
                    ]
                },
                "anchor_block_height": {
                    "oneOf": [ { "type": "null" }, { "type": "integer", "minimum": 0 } ]
                }
            }
        })
    }

    /// Hand-curated `EvidenceBundle` v1 schema.
    pub fn evidence_bundle_v1() -> serde_json::Value {
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": "https://aethelred.network/schemas/evidence_bundle/v1.json",
            "title": "EvidenceBundle",
            "description": "Exported tamper-evident bundle of seals.",
            "type": "object",
            "required": ["bundle_id", "tenant_id", "sector", "entries",
                         "merkle_root", "exported_at"],
            "properties": {
                "bundle_id": { "type": "string", "format": "uuid" },
                "tenant_id": { "type": "string", "minLength": 1 },
                "sector": {
                    "type": "string",
                    "enum": ["finance", "healthcare", "defense", "supply_chain",
                             "ai_agents", "autonomous_mobility", "research"]
                },
                "entries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["index", "seal", "leaf_hash"],
                        "properties": {
                            "index": { "type": "integer", "minimum": 0 },
                            "seal": { "$ref": "https://aethelred.network/schemas/digital_seal/v1.json" },
                            "leaf_hash": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                        }
                    }
                },
                "merkle_root": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "exported_at": { "type": "string", "format": "date-time" }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_bundle_generates_three_schemas() {
        let b = SchemaBundle::generate();
        assert!(b.digital_seal.is_object());
        assert!(b.seal_envelope.is_object());
        assert!(b.evidence_bundle.is_object());
    }

    #[test]
    fn pretty_json_includes_seal_id_field() {
        let b = SchemaBundle::generate();
        let s = b.to_pretty_json();
        assert!(s.contains("seal_id"));
        assert!(s.contains("merkle_root"));
        assert!(s.contains("evidence_bundle"));
    }

    #[test]
    fn digital_seal_schema_is_draft7() {
        let s = SchemaBundle::digital_seal_v1();
        assert_eq!(
            s.get("$schema").and_then(|v| v.as_str()),
            Some("http://json-schema.org/draft-07/schema#")
        );
    }

    #[test]
    fn digital_seal_schema_lists_all_required_fields() {
        let s = SchemaBundle::digital_seal_v1();
        let req = s
            .get("required")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<&str>>())
            .unwrap_or_default();
        for must in [
            "schema_version", "seal_id", "timestamp", "sector", "event_type",
            "event_hash", "model", "policy_id", "input_hash", "output_hash",
            "approvals", "tenant_id", "workflow_id", "jurisdiction_tag",
            "retention",
        ] {
            assert!(req.contains(&must), "missing required field: {must}");
        }
    }

    #[test]
    fn seal_envelope_schema_references_digital_seal() {
        let s = SchemaBundle::seal_envelope_v1();
        let s_str = serde_json::to_string(&s).unwrap();
        assert!(s_str.contains("digital_seal/v1.json"));
    }

    #[test]
    fn evidence_bundle_schema_lists_all_required_fields() {
        let s = SchemaBundle::evidence_bundle_v1();
        let req = s
            .get("required")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<&str>>())
            .unwrap_or_default();
        for must in [
            "bundle_id", "tenant_id", "sector", "entries", "merkle_root", "exported_at",
        ] {
            assert!(req.contains(&must), "missing required field: {must}");
        }
    }

    #[test]
    fn schema_bundle_serde_roundtrip() {
        let b = SchemaBundle::generate();
        let j = serde_json::to_string(&b).unwrap();
        let p: SchemaBundle = serde_json::from_str(&j).unwrap();
        assert_eq!(p.digital_seal, b.digital_seal);
    }
}
