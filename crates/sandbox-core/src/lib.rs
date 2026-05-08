//! # Aethelred Infinity Sandbox — Core
//!
//! Foundation crate for the seven sector-specific Aethelred Infinity Sandboxes:
//! Finance, Healthcare, Defense, Supply Chain, AI Agents, Autonomous Mobility,
//! and Research.
//!
//! This crate is intentionally **not** a sandbox by itself. It exposes the
//! production-grade primitives that every sector crate composes:
//!
//! - [`DigitalSeal`] — the canonical Aethelred AI-event evidence object.
//! - [`Workflow`] — the universal sector-workflow contract.
//! - [`SandboxBuilder`] — the plug-and-play entry point used by every sector.
//! - [`PolicyEngine`] — fail-closed policy gating.
//! - [`EvidenceLog`] — tamper-evident, Merkle-anchored log of seals.
//! - [`tee::Attestation`] — Intel TDX / AMD SEV-SNP / AWS Nitro / H100 / ARM CCA.
//! - [`zkml::ProofSystem`] — EZKL / RISC Zero / Plonky2 / Modulus / Groth16 selector.
//! - [`Connector`] — the customer-side data-source adapter (FHIR / OPC-UA /
//!   Kafka / FIX / etc.). Sector crates ship concrete implementations.
//!
//! ## Plug-and-play (5 lines)
//!
//! ```ignore
//! use aethelred_sandbox_finance::{FinanceSandbox, CreditDecision};
//!
//! let sandbox = FinanceSandbox::quickstart("FAB")?;
//! let seal = sandbox.seal_credit_decision(CreditDecision::demo())?;
//! println!("Seal: {}", seal.id);
//! ```
//!
//! See the per-sector crate documentation for the typed methods exposed by
//! each sector sandbox.
//!
//! ## Crypto provenance
//!
//! With the `real-crypto` feature (default), this crate uses
//! `aethelred-core::crypto` — the same SHA-256, Merkle-tree, and
//! ECDSA + CRYSTALS-Dilithium-3 hybrid signature primitives that the mainnet
//! protocol uses. Sandbox seals are byte-for-byte indistinguishable from
//! production seals.
//!
//! ## Backwards compatibility
//!
//! The legacy `aethelred-sandbox::enterprise_sandboxes` API is preserved by
//! the umbrella `aethelred-sandbox` crate. New work should target the
//! sector-specific crates.

#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::too_many_arguments)]

pub mod access_certification;
pub mod adversarial_detector;
pub mod agent_guardrail;
pub mod agent_session;
pub mod alert_router;
pub mod anchor;
pub mod anomaly;
pub mod anti_replay;
pub mod api_key_management;
pub mod api_versioning;
pub mod approval_workflow;
#[cfg(feature = "async")]
pub mod async_api;
#[cfg(feature = "async")]
pub mod async_persistence;
pub mod audit;
pub mod audit_archival;
pub mod audit_finding_tracker;
pub mod automated_decision_appeal;
pub mod backup_restore;
pub mod bias_detection;
pub mod billing_meter;
pub mod bring_your_own_key;
pub mod budget_register;
pub mod business_continuity;
pub mod canary_deployment;
pub mod capability_token;
pub mod case_management;
pub mod certification_lifecycle;
pub mod chaos_inject;
pub mod change_advisory_board;
pub mod chargeback_report;
pub mod compliance_dashboard;
pub mod compliance_report;
pub mod content_archive;
pub mod content_moderation;
pub mod control_test_register;
pub mod cost_attribution;
pub mod connector;
pub mod connector_jsonl;
pub mod cross_chain_anchor;
pub mod crypto_shred;
pub mod customer_consent;
pub mod customer_health;
pub mod crypto_signing;
pub mod dashboard_widget;
pub mod data_processing_agreement;
pub mod data_quality_monitor;
pub mod data_residency;
pub mod dataset_lineage;
pub mod dpia_register;
pub mod deployment_calendar;
pub mod deployment_pipeline;
pub mod differential_privacy;
pub mod disaster_recovery;
pub mod distributed_lock;
pub mod drift;
pub mod edge_node_registry;
pub mod encryption_inventory;
pub mod enterprise_risk_register;
pub mod error;
pub mod error_code;
pub mod escalation_matrix;
pub mod error_taxonomy;
pub mod evidence;
pub mod evidence_packager;
pub mod evidence_search;
pub mod explainability_log;
pub mod export_format;
pub mod feature_store_freshness;
pub mod feature_store_provenance;
pub mod forensic_capture;
pub mod feature_announcement;
pub mod feature_flag;
pub mod federated_verify;
pub mod fixtures;
pub mod gdpr_erasure;
pub mod hashing;
pub mod health;
pub mod hsm;
pub mod http_api;
pub mod human_review_queue;
pub mod identity_lifecycle;
pub mod identity_proofing;
pub mod incident;
pub mod incident_drill;
pub mod incident_postmortem;
pub mod incident_war_room;
pub mod inference_audit;
pub mod internal_messaging;
pub mod lineage;
pub mod llm_cost_meter;
pub mod log_aggregation;
pub mod policy;
pub mod prelude;
pub mod prompt_registry;
pub mod metrics;
pub mod model_card;
pub mod model_evaluation_harness;
pub mod model_risk_register;
pub mod multi_region_replication;
pub mod rate_card_versioning;
pub mod rate_limit;
pub mod on_call_schedule;
pub mod openlineage;
pub mod opentelemetry_trace;
pub mod operational_baseline;
pub mod outage_register;
pub mod persistence;
pub mod pii_redaction;
pub mod policy_dsl;
pub mod privacy_budget_tracker;
pub mod privacy_request_register;
pub mod privileged_access_register;
pub mod policy_versioning;
pub mod red_team_log;
pub mod refund_register;
pub mod regulatory_change;
pub mod regulatory_correspondence;
pub mod release_notes;
pub mod report_scheduler;
pub mod replay;
pub mod request_tracing;
pub mod retention_purge;
pub mod retention_register;
pub mod retry_policy;
pub mod risk_appetite;
pub mod runbook_engine;
pub mod sandbox;
pub mod sandbox_clone;
pub mod sandbox_template;
pub mod scanner;
pub mod schema_migration;
pub mod secrets_rotation;
pub mod sla_contract;
pub mod slo_tracking;
pub mod sso_integration;
pub mod status_page;
pub mod streaming_connector;
pub mod streaming_export;
pub mod subgroup_robustness;
pub mod subprocessor_register;
pub mod supply_chain_sbom;
#[cfg(feature = "schema")]
pub mod schema;
pub mod seal;
pub mod sector;
pub mod segregation_of_duties;
pub mod service_catalog;
pub mod service_map;
pub mod shadow_mode;
pub mod tee;
pub mod tee_verify;
pub mod tenant;
pub mod tenant_lifecycle;
pub mod tenant_quota_alerts;
pub mod third_party_risk;
pub mod threshold_signing;
pub mod time_machine;
pub mod time_query;
pub mod tool_invocation;
pub mod token_delegation;
pub mod training_run;
pub mod user_session;
pub mod vendor_assessment;
pub mod vendor_offboarding;
pub mod verify;
pub mod vulnerability_disclosure;
pub mod webhook_replay;
pub mod webhook_subscriptions;
pub mod workflow;
pub mod workflow_templates;
pub mod workspace_audit;
pub mod zkml;
pub mod zkml_verify;

// Top-level re-exports — the canonical public surface.
pub use audit::{AuditEntry, AuditFormat, AuditTrail};
pub use connector::{Connector, ConnectorConfig, ConnectorMetadata};
pub use error::{SandboxError, SandboxResult};
pub use error_code::{ErrorCategory, ErrorCode, ENTERPRISE_API_VERSION};
pub use evidence::{EvidenceBundle, EvidenceLog, EvidenceLogEntry, MerkleProof};
pub use fixtures::{Fixture, FixtureCatalog};
pub use hashing::{Hasher, Sha256Digest};
pub use policy::{Decision, PolicyEngine, PolicyGate, PolicyOutcome};
pub use sandbox::{Sandbox, SandboxBuilder, SandboxConfig, SandboxMetadata};
pub use seal::{
    ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealEnvelope, SealVersion,
};
pub use sector::{Sector, SectorMetadata};
pub use tee::{Attestation, AttestationVendor, TeePlatform};
pub use verify::{VerificationReport, Verifier};
pub use workflow::{Workflow, WorkflowContext, WorkflowEvent, WorkflowEventClass};
pub use zkml::{ProofArtefact, ProofSystem};
