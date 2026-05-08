//! Audit trail formatter.
//!
//! Auditors and compliance officers don't read JSON. This module turns an
//! [`crate::EvidenceBundle`] (or any sequence of [`crate::DigitalSeal`]s)
//! into a presentable audit trail in three formats:
//!
//! - [`AuditFormat::PlainText`] — `printk`-style chronological narrative.
//! - [`AuditFormat::Markdown`] — drop-in for compliance reports / Confluence /
//!   Notion.
//! - [`AuditFormat::Csv`] — drop-in for SOC2 / SOX paperwork.
//!
//! ## Usage
//!
//! ```ignore
//! use aethelred_sandbox_core::prelude::*;
//!
//! let bundle: EvidenceBundle = sandbox.evidence().export("FAB", Sector::Finance)?;
//! let trail = AuditTrail::from_bundle(&bundle);
//! let md = trail.render(AuditFormat::Markdown);
//! std::fs::write("audit.md", md).unwrap();
//! ```
//!
//! ## What is rendered
//!
//! For each seal, the trail emits:
//!
//! - Position in the bundle, timestamp, jurisdiction, tenant.
//! - Workflow id and event type.
//! - Model id + hash (truncated to 12-char prefix).
//! - Policy id, retention class.
//! - Approver count + decisions.
//! - Attestation platform (or `none`).
//! - zkML proof system (or `none`).
//! - Validator signature presence.
//!
//! Hashes (input/output/event) are emitted as 12-char prefixes; full hashes are
//! available in the underlying `EvidenceBundle` JSON. This matches the auditor
//! reading pattern (skim → spot check) without overwhelming the page.

use crate::evidence::{EvidenceBundle, EvidenceLogEntry};
use crate::seal::DigitalSeal;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

/// Render format for an audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFormat {
    /// Plain-text narrative.
    PlainText,
    /// Markdown — H2 + tables.
    Markdown,
    /// CSV — single header row + one row per seal.
    Csv,
}

/// One audit-trail entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Position in the trail (0-based).
    pub position: u64,
    /// Seal id (`seal_<uuid>`).
    pub seal_id: String,
    /// Timestamp in RFC 3339 format.
    pub timestamp: String,
    /// Tenant id.
    pub tenant_id: String,
    /// Sector.
    pub sector: crate::Sector,
    /// Workflow id.
    pub workflow_id: String,
    /// Event type discriminator.
    pub event_type: String,
    /// Model id.
    pub model_id: String,
    /// Truncated model hash (12-char prefix).
    pub model_hash_short: String,
    /// Truncated event hash (12-char prefix).
    pub event_hash_short: String,
    /// Truncated input hash (12-char prefix).
    pub input_hash_short: String,
    /// Truncated output hash (12-char prefix).
    pub output_hash_short: String,
    /// Policy id.
    pub policy_id: String,
    /// Retention class as string.
    pub retention: String,
    /// Jurisdiction tag.
    pub jurisdiction: String,
    /// Number of approvals.
    pub approvals: u32,
    /// Comma-separated approval decisions.
    pub decisions: String,
    /// Attestation platform (or `"none"`).
    pub attestation: String,
    /// zkML proof system (or `"none"`).
    pub zk_proof: String,
    /// `true` if a validator signature is present.
    pub has_validator_signature: bool,
}

impl AuditEntry {
    /// Build from a seal at a given position.
    pub fn from_seal(position: u64, seal: &DigitalSeal) -> Self {
        let timestamp = seal
            .timestamp
            .format(&Rfc3339)
            .unwrap_or_else(|_| "<unparseable>".into());
        let trunc = |s: String| s.chars().take(12).collect::<String>();
        Self {
            position,
            seal_id: seal.id_string(),
            timestamp,
            tenant_id: seal.tenant_id.clone(),
            sector: seal.sector,
            workflow_id: seal.workflow_id.clone(),
            event_type: seal.event_type.clone(),
            model_id: seal.model.model_id.clone(),
            model_hash_short: trunc(seal.model.model_hash.to_hex()),
            event_hash_short: trunc(seal.event_hash.to_hex()),
            input_hash_short: trunc(seal.input_hash.to_hex()),
            output_hash_short: trunc(seal.output_hash.to_hex()),
            policy_id: seal.policy_id.clone(),
            retention: format!("{:?}", seal.retention),
            jurisdiction: seal.jurisdiction_tag.clone(),
            approvals: seal.approvals.len() as u32,
            decisions: seal
                .approvals
                .iter()
                .map(|a| a.decision.as_str())
                .collect::<Vec<_>>()
                .join(","),
            attestation: seal
                .attestation
                .as_ref()
                .map(|a| a.vendor.platform.as_str().to_string())
                .unwrap_or_else(|| "none".into()),
            zk_proof: seal
                .zk_proof
                .as_ref()
                .map(|p| p.system.as_str().to_string())
                .unwrap_or_else(|| "none".into()),
            has_validator_signature: seal.validator_signature_hex.is_some(),
        }
    }

    /// Build from an evidence-log entry.
    pub fn from_entry(entry: &EvidenceLogEntry) -> Self {
        Self::from_seal(entry.index, &entry.seal)
    }
}

/// Full audit trail — one entry per seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    /// Tenant id.
    pub tenant_id: String,
    /// Sector.
    pub sector: crate::Sector,
    /// Generation timestamp.
    pub generated_at: String,
    /// Total entries.
    pub total: usize,
    /// All audit entries.
    pub entries: Vec<AuditEntry>,
}

impl AuditTrail {
    /// Build from an evidence bundle.
    pub fn from_bundle(bundle: &EvidenceBundle) -> Self {
        let entries: Vec<AuditEntry> = bundle
            .entries
            .iter()
            .map(AuditEntry::from_entry)
            .collect();
        Self {
            tenant_id: bundle.tenant_id.clone(),
            sector: bundle.sector,
            generated_at: bundle.exported_at.clone(),
            total: entries.len(),
            entries,
        }
    }

    /// Build from a slice of seals (e.g., for ad-hoc inspection).
    pub fn from_seals(
        tenant_id: impl Into<String>,
        sector: crate::Sector,
        seals: &[DigitalSeal],
    ) -> Self {
        let entries: Vec<AuditEntry> = seals
            .iter()
            .enumerate()
            .map(|(i, s)| AuditEntry::from_seal(i as u64, s))
            .collect();
        Self {
            tenant_id: tenant_id.into(),
            sector,
            generated_at: time::OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| String::new()),
            total: entries.len(),
            entries,
        }
    }

    /// Render in the requested format.
    pub fn render(&self, format: AuditFormat) -> String {
        match format {
            AuditFormat::PlainText => self.render_plain(),
            AuditFormat::Markdown => self.render_markdown(),
            AuditFormat::Csv => self.render_csv(),
        }
    }

    fn render_plain(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Aethelred Audit Trail — tenant={} sector={:?} generated_at={} total={}\n",
            self.tenant_id, self.sector, self.generated_at, self.total
        ));
        out.push_str(&"=".repeat(78));
        out.push('\n');
        for e in &self.entries {
            out.push_str(&format!(
                "[{:>4}] {} {} {:?}/{}\n",
                e.position, e.timestamp, e.seal_id, e.sector, e.workflow_id
            ));
            out.push_str(&format!(
                "       model={} ({}…) policy={} retention={}\n",
                e.model_id, e.model_hash_short, e.policy_id, e.retention
            ));
            out.push_str(&format!(
                "       approvals={} decisions=[{}] att={} zk={} sig={}\n",
                e.approvals,
                e.decisions,
                e.attestation,
                e.zk_proof,
                e.has_validator_signature
            ));
        }
        out
    }

    fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("## Aethelred Audit Trail — {}\n\n", self.tenant_id));
        out.push_str(&format!(
            "- **Sector**: {:?}\n- **Generated at**: {}\n- **Total seals**: {}\n\n",
            self.sector, self.generated_at, self.total
        ));
        out.push_str("| # | Timestamp | Workflow | Model | Policy | Approvals | Att | zk | Sig |\n");
        out.push_str("|---|-----------|----------|-------|--------|-----------|-----|----|-----|\n");
        for e in &self.entries {
            out.push_str(&format!(
                "| {} | {} | {} | {} ({}…) | {} | {} ({}) | {} | {} | {} |\n",
                e.position,
                e.timestamp,
                e.workflow_id,
                e.model_id,
                e.model_hash_short,
                e.policy_id,
                e.approvals,
                e.decisions,
                e.attestation,
                e.zk_proof,
                if e.has_validator_signature { "yes" } else { "no" }
            ));
        }
        out
    }

    fn render_csv(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "position,seal_id,timestamp,tenant,sector,workflow,event_type,model,model_hash,event_hash,input_hash,output_hash,policy,retention,jurisdiction,approvals,decisions,attestation,zk_proof,validator_signature\n",
        );
        for e in &self.entries {
            out.push_str(&format!(
                "{},{},{},{},{:?},{},{},{},{},{},{},{},{},{},{},{},\"{}\",{},{},{}\n",
                e.position,
                e.seal_id,
                e.timestamp,
                csv_quote(&e.tenant_id),
                e.sector,
                e.workflow_id,
                e.event_type,
                e.model_id,
                e.model_hash_short,
                e.event_hash_short,
                e.input_hash_short,
                e.output_hash_short,
                e.policy_id,
                e.retention,
                e.jurisdiction,
                e.approvals,
                e.decisions,
                e.attestation,
                e.zk_proof,
                e.has_validator_signature,
            ));
        }
        out
    }
}

fn csv_quote(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::Hasher;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use crate::tee::{Attestation, TeePlatform};
    use crate::zkml::{ProofArtefact, ProofSystem};
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal_with_artefacts() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("credit_risk_v3.2", Hasher::sha256(b"weights")),
            policy_id: "po_credit_v1".into(),
            input_hash: Hasher::sha256(b"input"),
            output_hash: Hasher::sha256(b"output"),
            approvals: vec![
                ApprovalRecord::unsigned("u#1", "underwriter", "approved"),
                ApprovalRecord::unsigned("u#2", "compliance", "concur"),
            ],
            attestation: Some(Attestation::mock(
                TeePlatform::IntelTdx,
                Hasher::sha256(b"nonce"),
            )),
            zk_proof: Some(ProofArtefact::placeholder(ProofSystem::Ezkl)),
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: Some("deadbeef".into()),
        }
    }

    fn dummy_seal_minimal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Healthcare,
            event_type: "clinical_inference".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("med_v1", Hasher::sha256(b"med-weights")),
            policy_id: "po_med_v1".into(),
            input_hash: Hasher::sha256(b"in"),
            output_hash: Hasher::sha256(b"out"),
            approvals: vec![],
            attestation: None,
            zk_proof: None,
            tenant_id: "SKMC".into(),
            workflow_id: "clinical_ai".into(),
            jurisdiction_tag: "AE-DOH".into(),
            retention: RetentionClass::TenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn entry_truncates_hashes_to_12_chars() {
        let s = dummy_seal_with_artefacts();
        let e = AuditEntry::from_seal(0, &s);
        assert_eq!(e.model_hash_short.len(), 12);
        assert_eq!(e.event_hash_short.len(), 12);
        assert_eq!(e.input_hash_short.len(), 12);
        assert_eq!(e.output_hash_short.len(), 12);
    }

    #[test]
    fn entry_records_attestation_platform() {
        let s = dummy_seal_with_artefacts();
        let e = AuditEntry::from_seal(0, &s);
        assert_eq!(e.attestation, "intel_tdx");
    }

    #[test]
    fn entry_records_zk_system() {
        let s = dummy_seal_with_artefacts();
        let e = AuditEntry::from_seal(0, &s);
        assert_eq!(e.zk_proof, "ezkl");
    }

    #[test]
    fn entry_handles_missing_artefacts() {
        let s = dummy_seal_minimal();
        let e = AuditEntry::from_seal(7, &s);
        assert_eq!(e.attestation, "none");
        assert_eq!(e.zk_proof, "none");
        assert!(!e.has_validator_signature);
    }

    #[test]
    fn entry_records_decision_csv() {
        let s = dummy_seal_with_artefacts();
        let e = AuditEntry::from_seal(0, &s);
        assert_eq!(e.decisions, "approved,concur");
    }

    #[test]
    fn trail_from_seals_sets_metadata() {
        let seals = [dummy_seal_with_artefacts(), dummy_seal_minimal()];
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        assert_eq!(t.tenant_id, "FAB");
        assert_eq!(t.sector, Sector::Finance);
        assert_eq!(t.total, 2);
    }

    #[test]
    fn render_plaintext_includes_header() {
        let seals = [dummy_seal_with_artefacts()];
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        let out = t.render(AuditFormat::PlainText);
        assert!(out.contains("Aethelred Audit Trail"));
        assert!(out.contains("FAB"));
    }

    #[test]
    fn render_markdown_includes_table_header() {
        let seals = [dummy_seal_with_artefacts()];
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        let out = t.render(AuditFormat::Markdown);
        assert!(out.contains("|"));
        assert!(out.contains("Workflow"));
    }

    #[test]
    fn render_csv_includes_header_row() {
        let seals = [dummy_seal_with_artefacts()];
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        let out = t.render(AuditFormat::Csv);
        assert!(out.starts_with("position,seal_id,timestamp,"));
        assert!(out.lines().count() >= 2);
    }

    #[test]
    fn render_csv_one_data_row_per_seal() {
        let seals: Vec<DigitalSeal> = (0..5).map(|_| dummy_seal_with_artefacts()).collect();
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        let csv = t.render(AuditFormat::Csv);
        // header + 5 data rows
        assert_eq!(csv.lines().count(), 6);
    }

    #[test]
    fn audit_serde_roundtrip() {
        let seals = [dummy_seal_with_artefacts()];
        let t = AuditTrail::from_seals("FAB", Sector::Finance, &seals);
        let j = serde_json::to_string(&t).unwrap();
        let p: AuditTrail = serde_json::from_str(&j).unwrap();
        assert_eq!(p.total, t.total);
        assert_eq!(p.tenant_id, t.tenant_id);
    }

    #[test]
    fn csv_quote_escapes_commas_and_quotes() {
        assert_eq!(csv_quote("simple"), "simple");
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("he said \"hi\""), "\"he said \"\"hi\"\"\"");
    }

    #[test]
    fn entry_serde_roundtrip() {
        let s = dummy_seal_with_artefacts();
        let e = AuditEntry::from_seal(3, &s);
        let j = serde_json::to_string(&e).unwrap();
        let p: AuditEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(p.seal_id, e.seal_id);
        assert_eq!(p.workflow_id, e.workflow_id);
    }
}
