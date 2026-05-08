//! Auto-generated compliance reports.
//!
//! Bridges Aethelred evidence bundles into the shapes auditors expect for:
//!
//! - **SOC 2 Type II** — control families CC1..CC9 (AICPA TSC 2017).
//! - **ISO/IEC 27001:2022** — Annex A controls (93 in total).
//! - **HIPAA Security Rule** — Administrative / Physical / Technical
//!   safeguards (45 CFR §§ 164.308 / 164.310 / 164.312).
//! - **GDPR / UAE PDPL / Saudi PDPL** — Article 5/30/32 records of
//!   processing, lawful-basis tracking, breach notifications.
//!
//! ## API shape
//!
//! - [`ControlMapping`] — maps a sandbox-internal `gate_id` /
//!   `error_code` → external control id (e.g., `"CC6.1"`, `"A.5.30"`).
//! - [`ComplianceFramework`] — discriminator for SOC 2 / ISO 27001 / HIPAA / GDPR.
//! - [`ComplianceReport`] — generated report with sections per control,
//!   each citing seal ids that satisfy or test the control.
//! - [`ReportRenderer`] — renders to Markdown, CSV, or JSON.
//!
//! ## What this gives you
//!
//! Instead of a manual spreadsheet at audit time, you run:
//!
//! ```ignore
//! let mapper = ControlMapping::soc2_default();
//! let report = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &mapper);
//! std::fs::write("audit/soc2-2026-q1.md", report.to_markdown())?;
//! ```
//!
//! ...and you have a control-by-control evidence trail that the auditor can
//! click through to seal ids in your evidence log.

use crate::evidence::EvidenceBundle;
use crate::hashing::Sha256Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use uuid::Uuid;

// =============================================================================
// ComplianceFramework
// =============================================================================

/// Compliance framework discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    /// AICPA SOC 2 Type II.
    Soc2,
    /// ISO/IEC 27001:2022.
    Iso27001,
    /// HIPAA Security Rule (45 CFR §§ 164.308 / 164.310 / 164.312).
    Hipaa,
    /// EU GDPR.
    Gdpr,
    /// UAE PDPL (Federal Decree-Law No. 45 of 2021).
    UaePdpl,
    /// Saudi PDPL (Royal Decree M/19).
    SaudiPdpl,
    /// Singapore PDPA.
    SingaporePdpa,
}

impl ComplianceFramework {
    /// Stable string id.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Soc2 => "soc2",
            Self::Iso27001 => "iso_27001",
            Self::Hipaa => "hipaa",
            Self::Gdpr => "gdpr",
            Self::UaePdpl => "uae_pdpl",
            Self::SaudiPdpl => "saudi_pdpl",
            Self::SingaporePdpa => "singapore_pdpa",
        }
    }
}

// =============================================================================
// Control + ControlMapping
// =============================================================================

/// One external control reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlRef {
    /// Framework id.
    pub framework: ComplianceFramework,
    /// External control id (e.g., `"CC6.1"`, `"A.5.30"`, `"§ 164.312(a)(1)"`).
    pub control_id: String,
    /// Human-readable title.
    pub title: String,
    /// Plain-English description.
    pub description: String,
}

/// Maps internal sandbox identifiers (gate ids, workflow ids) to external
/// control references.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlMapping {
    /// `(internal_id) → list of external controls`.
    pub mappings: BTreeMap<String, Vec<ControlRef>>,
}

impl ControlMapping {
    /// Empty mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one mapping.
    pub fn add(&mut self, internal_id: impl Into<String>, control: ControlRef) -> &mut Self {
        self.mappings
            .entry(internal_id.into())
            .or_default()
            .push(control);
        self
    }

    /// Retrieve all controls for an internal id.
    pub fn get(&self, internal_id: &str) -> &[ControlRef] {
        self.mappings
            .get(internal_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Number of distinct internal ids mapped.
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// `true` if no mappings.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// SOC 2 default mapping for the workflow ids we ship.
    pub fn soc2_default() -> Self {
        let mut m = Self::new();
        m.add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC6.1".into(),
                title: "Logical Access Security Software".into(),
                description:
                    "The entity implements logical access security software, infrastructure, and architectures over protected information assets."
                        .into(),
            },
        )
        .add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC7.2".into(),
                title: "System Monitoring".into(),
                description: "Monitors system components for anomalies indicative of security events.".into(),
            },
        )
        .add(
            "aml_screening",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC2.2".into(),
                title: "Internal Communication".into(),
                description: "Communicates internally about responsibilities and procedures.".into(),
            },
        )
        .add(
            "clinical_inference",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC8.1".into(),
                title: "Change Management".into(),
                description: "Authorizes, designs, develops, configures, and tests changes.".into(),
            },
        );
        m
    }

    /// ISO 27001 default mapping.
    pub fn iso_27001_default() -> Self {
        let mut m = Self::new();
        m.add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Iso27001,
                control_id: "A.5.30".into(),
                title: "ICT readiness for business continuity".into(),
                description: "ICT readiness shall be planned, implemented, maintained and tested.".into(),
            },
        )
        .add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Iso27001,
                control_id: "A.8.16".into(),
                title: "Monitoring activities".into(),
                description: "Networks, systems and applications shall be monitored for anomalous behaviour.".into(),
            },
        )
        .add(
            "aml_screening",
            ControlRef {
                framework: ComplianceFramework::Iso27001,
                control_id: "A.5.34".into(),
                title: "Privacy and protection of PII".into(),
                description: "Privacy and protection of PII shall be identified and met.".into(),
            },
        );
        m
    }

    /// HIPAA Security Rule default mapping (clinical workflows).
    pub fn hipaa_default() -> Self {
        let mut m = Self::new();
        m.add(
            "clinical_inference",
            ControlRef {
                framework: ComplianceFramework::Hipaa,
                control_id: "§ 164.312(a)(1)".into(),
                title: "Access Control".into(),
                description: "Implement technical policies for unique user identification + emergency access procedures.".into(),
            },
        )
        .add(
            "clinical_inference",
            ControlRef {
                framework: ComplianceFramework::Hipaa,
                control_id: "§ 164.312(b)".into(),
                title: "Audit Controls".into(),
                description: "Implement hardware, software, and procedural mechanisms that record and examine activity.".into(),
            },
        )
        .add(
            "claims_adjudication",
            ControlRef {
                framework: ComplianceFramework::Hipaa,
                control_id: "§ 164.312(c)(1)".into(),
                title: "Integrity".into(),
                description: "Implement policies to protect ePHI from improper alteration or destruction.".into(),
            },
        );
        m
    }

    /// GDPR default mapping.
    pub fn gdpr_default() -> Self {
        let mut m = Self::new();
        m.add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Gdpr,
                control_id: "Art. 22".into(),
                title: "Automated individual decision-making".into(),
                description: "Right not to be subject to a decision based solely on automated processing.".into(),
            },
        )
        .add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Gdpr,
                control_id: "Art. 30".into(),
                title: "Records of processing activities".into(),
                description: "Each controller shall maintain a record of processing activities.".into(),
            },
        )
        .add(
            "credit_decision",
            ControlRef {
                framework: ComplianceFramework::Gdpr,
                control_id: "Art. 32".into(),
                title: "Security of processing".into(),
                description: "Implement appropriate technical and organisational measures.".into(),
            },
        );
        m
    }
}

// =============================================================================
// ComplianceReport
// =============================================================================

/// One section of the report — a control + the seal ids that evidence it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSection {
    /// External control reference.
    pub control: ControlRef,
    /// Seal ids that evidence this control.
    pub evidence_seal_ids: Vec<Uuid>,
    /// Earliest evidence timestamp.
    pub earliest_evidence: Option<String>,
    /// Latest evidence timestamp.
    pub latest_evidence: Option<String>,
    /// Total evidence count.
    pub total_evidence: u64,
}

impl ControlSection {
    /// `true` if at least one seal evidences this control.
    pub fn has_evidence(&self) -> bool {
        !self.evidence_seal_ids.is_empty()
    }
}

/// Auto-generated compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Report id.
    pub report_id: Uuid,
    /// Tenant.
    pub tenant_id: String,
    /// Framework.
    pub framework: ComplianceFramework,
    /// RFC 3339 generation timestamp.
    pub generated_at: String,
    /// Reporting window start (RFC 3339).
    pub window_start: Option<String>,
    /// Reporting window end (RFC 3339).
    pub window_end: Option<String>,
    /// Total seals analysed.
    pub total_seals_analysed: u64,
    /// Per-control sections.
    pub control_sections: Vec<ControlSection>,
    /// Bundle merkle root (provenance anchor).
    pub bundle_merkle_root: Sha256Digest,
}

impl ComplianceReport {
    /// Generate a report from an evidence bundle + control mapping.
    ///
    /// The mapping's keys are matched against each seal's `workflow_id`.
    pub fn generate(
        bundle: &EvidenceBundle,
        framework: ComplianceFramework,
        mapping: &ControlMapping,
    ) -> Self {
        // Collect controls grouped by control_id (deduped across workflows).
        let mut sections: BTreeMap<String, ControlSection> = BTreeMap::new();
        for entry in &bundle.entries {
            let workflow = &entry.seal.workflow_id;
            for control in mapping.get(workflow) {
                if control.framework != framework {
                    continue;
                }
                let section = sections.entry(control.control_id.clone()).or_insert_with(|| {
                    ControlSection {
                        control: control.clone(),
                        evidence_seal_ids: Vec::new(),
                        earliest_evidence: None,
                        latest_evidence: None,
                        total_evidence: 0,
                    }
                });
                section.evidence_seal_ids.push(entry.seal.seal_id);
                section.total_evidence += 1;
                let ts = entry
                    .seal
                    .timestamp
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default();
                section.earliest_evidence = Some(match &section.earliest_evidence {
                    Some(cur) if cur.as_str() <= ts.as_str() => cur.clone(),
                    _ => ts.clone(),
                });
                section.latest_evidence = Some(match &section.latest_evidence {
                    Some(cur) if cur.as_str() >= ts.as_str() => cur.clone(),
                    _ => ts,
                });
            }
        }
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default();
        let total_seals = bundle.entries.len() as u64;
        // Stable order: sort by control_id.
        let mut control_sections: Vec<ControlSection> = sections.into_values().collect();
        control_sections.sort_by(|a, b| a.control.control_id.cmp(&b.control.control_id));
        Self {
            report_id: Uuid::now_v7(),
            tenant_id: bundle.tenant_id.clone(),
            framework,
            generated_at: now,
            window_start: bundle
                .entries
                .first()
                .map(|e| e.seal.timestamp.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
            window_end: bundle
                .entries
                .last()
                .map(|e| e.seal.timestamp.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
            total_seals_analysed: total_seals,
            control_sections,
            bundle_merkle_root: bundle.merkle_root,
        }
    }

    /// Number of controls covered.
    pub fn covered_control_count(&self) -> usize {
        self.control_sections
            .iter()
            .filter(|s| s.has_evidence())
            .count()
    }

    /// Total number of evidence-seal references across all controls.
    pub fn total_evidence_references(&self) -> u64 {
        self.control_sections.iter().map(|s| s.total_evidence).sum()
    }

    /// Render to Markdown.
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Aethelred Compliance Report — {}\n\n",
            self.framework.as_str().to_uppercase()
        ));
        out.push_str(&format!("- **Tenant**: {}\n", self.tenant_id));
        out.push_str(&format!("- **Generated**: {}\n", self.generated_at));
        out.push_str(&format!(
            "- **Window**: {} → {}\n",
            self.window_start.as_deref().unwrap_or("-"),
            self.window_end.as_deref().unwrap_or("-")
        ));
        out.push_str(&format!(
            "- **Seals analysed**: {}\n",
            self.total_seals_analysed
        ));
        out.push_str(&format!(
            "- **Controls covered**: {}\n",
            self.covered_control_count()
        ));
        out.push_str(&format!(
            "- **Bundle Merkle root**: `{}`\n\n",
            self.bundle_merkle_root.to_hex()
        ));
        for s in &self.control_sections {
            out.push_str(&format!(
                "## {} — {}\n\n",
                s.control.control_id, s.control.title
            ));
            out.push_str(&format!("> {}\n\n", s.control.description));
            out.push_str(&format!(
                "- Evidence count: {}\n- Earliest: {}\n- Latest: {}\n\n",
                s.total_evidence,
                s.earliest_evidence.as_deref().unwrap_or("-"),
                s.latest_evidence.as_deref().unwrap_or("-")
            ));
            if !s.evidence_seal_ids.is_empty() {
                out.push_str("Evidence seal ids:\n\n");
                for id in s.evidence_seal_ids.iter().take(20) {
                    out.push_str(&format!("- `{}`\n", id));
                }
                if s.evidence_seal_ids.len() > 20 {
                    out.push_str(&format!(
                        "- … + {} more\n",
                        s.evidence_seal_ids.len() - 20
                    ));
                }
                out.push('\n');
            }
        }
        out
    }

    /// Render to CSV (one row per (control, seal)).
    pub fn to_csv(&self) -> String {
        let mut out = String::from(
            "framework,control_id,control_title,seal_id,earliest_evidence,latest_evidence,bundle_merkle_root\n",
        );
        for s in &self.control_sections {
            for id in &s.evidence_seal_ids {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    self.framework.as_str(),
                    s.control.control_id,
                    s.control.title.replace(',', ";"),
                    id,
                    s.earliest_evidence.as_deref().unwrap_or(""),
                    s.latest_evidence.as_deref().unwrap_or(""),
                    self.bundle_merkle_root.to_hex(),
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceLog;
    use crate::hashing::Hasher;
    use crate::seal::{ApprovalRecord, DigitalSeal, ModelReference, RetentionClass, SealVersion};
    use crate::Sector;
    use std::collections::BTreeMap as StdBTreeMap;

    fn seal_for_workflow(workflow: &str) -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: format!("{workflow}.event"),
            event_hash: Hasher::sha256(b"e"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"i"),
            output_hash: Hasher::sha256(b"o"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: workflow.into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: StdBTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    fn make_bundle(workflows: Vec<&str>) -> EvidenceBundle {
        let log = EvidenceLog::new();
        for w in workflows {
            log.append(seal_for_workflow(w)).unwrap();
        }
        log.export("FAB", Sector::Finance).unwrap()
    }

    #[test]
    fn framework_string_ids_unique() {
        let all = [
            ComplianceFramework::Soc2,
            ComplianceFramework::Iso27001,
            ComplianceFramework::Hipaa,
            ComplianceFramework::Gdpr,
            ComplianceFramework::UaePdpl,
            ComplianceFramework::SaudiPdpl,
            ComplianceFramework::SingaporePdpa,
        ];
        let mut ids: Vec<&str> = all.iter().map(|f| f.as_str()).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn soc2_default_includes_credit_decision() {
        let m = ControlMapping::soc2_default();
        let controls = m.get("credit_decision");
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.control_id == "CC6.1"));
    }

    #[test]
    fn iso27001_default_includes_credit_decision() {
        let m = ControlMapping::iso_27001_default();
        let controls = m.get("credit_decision");
        assert!(!controls.is_empty());
    }

    #[test]
    fn hipaa_default_includes_clinical() {
        let m = ControlMapping::hipaa_default();
        let controls = m.get("clinical_inference");
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.control_id.contains("164")));
    }

    #[test]
    fn gdpr_default_includes_credit() {
        let m = ControlMapping::gdpr_default();
        let controls = m.get("credit_decision");
        assert!(!controls.is_empty());
        assert!(controls.iter().any(|c| c.control_id == "Art. 22"));
    }

    #[test]
    fn add_appends_to_existing_workflow() {
        let mut m = ControlMapping::new();
        m.add(
            "wf",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC1.1".into(),
                title: "x".into(),
                description: "y".into(),
            },
        );
        m.add(
            "wf",
            ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "CC1.2".into(),
                title: "x".into(),
                description: "y".into(),
            },
        );
        assert_eq!(m.get("wf").len(), 2);
    }

    #[test]
    fn empty_mapping_returns_empty() {
        let m = ControlMapping::new();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert!(m.get("nope").is_empty());
    }

    #[test]
    fn report_generate_empty_bundle() {
        let bundle = make_bundle(vec![]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert_eq!(r.total_seals_analysed, 0);
        assert_eq!(r.control_sections.len(), 0);
    }

    #[test]
    fn report_covers_credit_decision_with_soc2() {
        let bundle = make_bundle(vec!["credit_decision", "credit_decision", "aml_screening"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert!(r.covered_control_count() > 0);
        let cc61 = r.control_sections.iter().find(|s| s.control.control_id == "CC6.1");
        assert!(cc61.is_some());
        assert_eq!(cc61.unwrap().total_evidence, 2);
    }

    #[test]
    fn report_skips_other_frameworks() {
        let bundle = make_bundle(vec!["credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Hipaa, &m);
        // SOC2 mappings only — no HIPAA controls — empty.
        assert_eq!(r.covered_control_count(), 0);
    }

    #[test]
    fn report_total_evidence_references_sums() {
        let bundle = make_bundle(vec![
            "credit_decision",
            "credit_decision",
            "credit_decision",
        ]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        // CC6.1 + CC7.2 each cover credit_decision → 3 + 3 = 6 references.
        assert_eq!(r.total_evidence_references(), 6);
    }

    #[test]
    fn report_to_markdown_includes_framework() {
        let bundle = make_bundle(vec!["credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        let md = r.to_markdown();
        assert!(md.contains("SOC2"));
        assert!(md.contains("CC6.1"));
    }

    #[test]
    fn report_to_csv_has_header_and_rows() {
        let bundle = make_bundle(vec!["credit_decision", "credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        let csv = r.to_csv();
        assert!(csv.starts_with("framework,control_id"));
        // 2 seals × 2 controls = 4 rows + 1 header.
        assert_eq!(csv.lines().count(), 5);
    }

    #[test]
    fn report_records_window_start_and_end() {
        let bundle = make_bundle(vec!["credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert!(r.window_start.is_some());
        assert!(r.window_end.is_some());
    }

    #[test]
    fn report_records_bundle_root() {
        let bundle = make_bundle(vec!["credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert_eq!(r.bundle_merkle_root, bundle.merkle_root);
    }

    #[test]
    fn report_serde_round_trip() {
        let bundle = make_bundle(vec!["credit_decision"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        let j = serde_json::to_string(&r).unwrap();
        let p: ComplianceReport = serde_json::from_str(&j).unwrap();
        assert_eq!(p.framework, r.framework);
        assert_eq!(p.total_seals_analysed, r.total_seals_analysed);
    }

    #[test]
    fn control_ref_serde_round_trip() {
        let c = ControlRef {
            framework: ComplianceFramework::Iso27001,
            control_id: "A.5.30".into(),
            title: "x".into(),
            description: "y".into(),
        };
        let j = serde_json::to_string(&c).unwrap();
        let p: ControlRef = serde_json::from_str(&j).unwrap();
        assert_eq!(p, c);
    }

    #[test]
    fn control_section_has_evidence_check() {
        let mut s = ControlSection {
            control: ControlRef {
                framework: ComplianceFramework::Soc2,
                control_id: "x".into(),
                title: "x".into(),
                description: "x".into(),
            },
            evidence_seal_ids: vec![],
            earliest_evidence: None,
            latest_evidence: None,
            total_evidence: 0,
        };
        assert!(!s.has_evidence());
        s.evidence_seal_ids.push(Uuid::now_v7());
        assert!(s.has_evidence());
    }

    #[test]
    fn iso_default_for_aml_screening() {
        let m = ControlMapping::iso_27001_default();
        let controls = m.get("aml_screening");
        assert!(!controls.is_empty());
    }

    #[test]
    fn many_seals_truncate_in_markdown() {
        let bundle = make_bundle(vec!["credit_decision"; 30]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        let md = r.to_markdown();
        // We render at most 20 ids per section; 10 are summarised.
        assert!(md.contains("more"));
    }

    #[test]
    fn covered_control_count_matches_sections_with_evidence() {
        let bundle = make_bundle(vec!["credit_decision", "aml_screening"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert_eq!(r.covered_control_count(), r.control_sections.len());
    }

    #[test]
    fn framework_serde_round_trip() {
        let f = ComplianceFramework::SaudiPdpl;
        let j = serde_json::to_string(&f).unwrap();
        assert_eq!(j, "\"saudi_pdpl\"");
        let p: ComplianceFramework = serde_json::from_str(&j).unwrap();
        assert_eq!(p, f);
    }

    #[test]
    fn unknown_workflow_produces_no_section() {
        let bundle = make_bundle(vec!["unknown_workflow"]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        assert_eq!(r.covered_control_count(), 0);
    }

    #[test]
    fn control_sections_sorted_by_control_id() {
        let bundle = make_bundle(vec![
            "credit_decision",
            "aml_screening",
            "credit_decision",
            "clinical_inference",
        ]);
        let m = ControlMapping::soc2_default();
        let r = ComplianceReport::generate(&bundle, ComplianceFramework::Soc2, &m);
        let ids: Vec<&str> = r
            .control_sections
            .iter()
            .map(|s| s.control.control_id.as_str())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
