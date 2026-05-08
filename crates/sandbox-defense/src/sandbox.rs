//! `DefenseSandbox` — plug-and-play entry point for defense workflows.

use crate::policy::{
    default_gates, GATE_AIR_GAP_RESPECTED, GATE_CLASSIFICATION_BOUNDARY, GATE_EVIDENCE_INTEGRITY,
    GATE_HUMAN_COMMAND_AUTHORITY, GATE_JURISDICTION_SUPPORTED, GATE_MODEL_APPROVAL,
    GATE_NON_WEAPONIZED_SCOPE, GATE_ODD_BOUNDARY, GATE_SOVEREIGNTY,
};
use crate::regulators::{DefenseJurisdiction, RegulatorView};
use crate::workflows::{
    autonomous_logistics::{self, AutonomousLogistics, AutonomousLogisticsSeal},
    cyber_defense::{self, CyberDefenseEvent, CyberDefenseSeal},
    inspection_qa::{self, InspectionQa, InspectionQaSeal},
    sensor_fusion::{self, SensorFusion, SensorFusionSeal},
};
use aethelred_sandbox_core::audit::{AuditFormat, AuditTrail};
use aethelred_sandbox_core::policy::PolicyGate;
use aethelred_sandbox_core::verify::{VerificationReport, Verifier};
use aethelred_sandbox_core::{
    DigitalSeal, EvidenceBundle, EvidenceLogEntry, Sandbox, SandboxBuilder, SandboxError,
    SandboxResult, SealEnvelope, Sector, Sha256Digest,
};
use std::collections::HashMap;

/// Plug-and-play entry point for defense workflows.
pub struct DefenseSandbox {
    inner: Sandbox,
    primary_jurisdiction: DefenseJurisdiction,
    air_gap: bool,
}

impl DefenseSandbox {
    /// One-line quickstart (Tawazun + UAE AF default; air-gap on).
    pub fn quickstart(institution: impl Into<String>) -> SandboxResult<Self> {
        Self::builder()
            .institution(institution)
            .jurisdiction(DefenseJurisdiction::TawazunUae)
            .air_gap(true)
            .build()
    }

    /// Builder.
    pub fn builder() -> DefenseSandboxBuilder {
        DefenseSandboxBuilder::default()
    }

    /// Underlying core sandbox.
    pub fn core(&self) -> &Sandbox {
        &self.inner
    }

    /// Primary jurisdiction.
    pub fn primary_jurisdiction(&self) -> DefenseJurisdiction {
        self.primary_jurisdiction
    }

    /// `true` if the sandbox is in air-gap mode.
    pub fn is_air_gap(&self) -> bool {
        self.air_gap
    }

    /// Tenant id (the institution).
    pub fn institution(&self) -> &str {
        &self.inner.config().tenant_id
    }

    fn append(&self, seal: DigitalSeal) -> SandboxResult<EvidenceLogEntry> {
        self.inner.append_seal(seal)
    }

    /// Export the evidence bundle.
    pub fn export_evidence(&self) -> SandboxResult<EvidenceBundle> {
        self.inner.export_evidence()
    }

    // ============ Enterprise convenience: bulk + audit + verify ============

    /// Seal a batch of autonomous-logistics steps.
    pub fn seal_autonomous_logistics_batch(
        &self,
        items: impl IntoIterator<Item = AutonomousLogistics>,
    ) -> SandboxResult<Vec<AutonomousLogisticsSeal>> {
        items.into_iter().map(|i| self.seal_autonomous_logistics(i)).collect()
    }

    /// Seal a batch of sensor-fusion events.
    pub fn seal_sensor_fusion_batch(
        &self,
        items: impl IntoIterator<Item = SensorFusion>,
    ) -> SandboxResult<Vec<SensorFusionSeal>> {
        items.into_iter().map(|i| self.seal_sensor_fusion(i)).collect()
    }

    /// Seal a batch of inspections.
    pub fn seal_inspection_batch(
        &self,
        items: impl IntoIterator<Item = InspectionQa>,
    ) -> SandboxResult<Vec<InspectionQaSeal>> {
        items.into_iter().map(|i| self.seal_inspection(i)).collect()
    }

    /// Seal a batch of cyber-defense events.
    pub fn seal_cyber_defense_batch(
        &self,
        items: impl IntoIterator<Item = CyberDefenseEvent>,
    ) -> SandboxResult<Vec<CyberDefenseSeal>> {
        items.into_iter().map(|i| self.seal_cyber_defense(i)).collect()
    }

    /// Get an envelope for the seal at `index`.
    pub fn envelope_at(&self, index: u64) -> SandboxResult<SealEnvelope> {
        let bundle = self.export_evidence()?;
        let entry = bundle
            .entries
            .iter()
            .find(|e| e.index == index)
            .cloned()
            .ok_or_else(|| {
                SandboxError::Evidence(format!("envelope at index {index} not found"))
            })?;
        let proof = self.inner.evidence().proof(index)?;
        Ok(SealEnvelope {
            seal: entry.seal,
            merkle_proof: Some(proof),
            anchor_block_height: None,
        })
    }

    /// Get all envelopes (against current root).
    pub fn all_envelopes(&self) -> SandboxResult<Vec<SealEnvelope>> {
        let bundle = self.export_evidence()?;
        let mut out = Vec::with_capacity(bundle.entries.len());
        for entry in bundle.entries {
            let proof = self.inner.evidence().proof(entry.index)?;
            out.push(SealEnvelope {
                seal: entry.seal,
                merkle_proof: Some(proof),
                anchor_block_height: None,
            });
        }
        Ok(out)
    }

    /// Current Merkle root.
    pub fn current_root(&self) -> SandboxResult<Sha256Digest> {
        self.inner.current_root()
    }

    /// Number of seals.
    pub fn seal_count(&self) -> usize {
        self.inner.seal_count()
    }

    /// Render audit trail.
    pub fn audit_trail(&self, format: AuditFormat) -> SandboxResult<String> {
        self.inner.audit_trail(format)
    }

    /// Build structured audit trail.
    pub fn audit_trail_struct(&self) -> SandboxResult<AuditTrail> {
        let bundle = self.export_evidence()?;
        Ok(AuditTrail::from_bundle(&bundle))
    }

    /// Verify all seals against current root.
    pub fn verify_all(&self) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        Verifier::default().verify_batch(&envs, root)
    }

    /// Verify all seals with a custom Verifier.
    pub fn verify_all_with(
        &self,
        verifier: &Verifier,
    ) -> SandboxResult<Vec<VerificationReport>> {
        let envs = self.all_envelopes()?;
        let root = self.current_root()?;
        verifier.verify_batch(&envs, root)
    }

    /// Project a seal into a regulator-shape view.
    pub fn regulator_view(
        &self,
        seal: &DigitalSeal,
        jurisdiction: DefenseJurisdiction,
    ) -> RegulatorView {
        let event_class = seal.event_type.split('.').next().unwrap_or("event").to_string();
        let decision = seal
            .approvals
            .first()
            .map(|a| a.decision.clone())
            .unwrap_or_else(|| "unknown".into());
        RegulatorView::project(seal, jurisdiction, decision, event_class)
    }

    fn common_faults(&self, seal: &DigitalSeal) -> HashMap<String, bool> {
        let mut faults: HashMap<String, bool> = HashMap::new();
        if seal.model.model_hash.0 == [0u8; 32] {
            faults.insert(GATE_MODEL_APPROVAL.into(), true);
        }
        if seal.approvals.is_empty() {
            faults.insert(GATE_HUMAN_COMMAND_AUTHORITY.into(), true);
        }
        if !is_supported_jurisdiction(&seal.jurisdiction_tag) {
            faults.insert(GATE_JURISDICTION_SUPPORTED.into(), true);
        }
        // Non-weaponised scope must be flagged true on the seal.
        let nws = seal
            .sector_extension
            .get("non_weaponized_scope")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !nws {
            faults.insert(GATE_NON_WEAPONIZED_SCOPE.into(), true);
        }
        // Evidence integrity.
        if seal.event_hash.0 == [0u8; 32] || seal.input_hash.0 == [0u8; 32] || seal.output_hash.0 == [0u8; 32] {
            faults.insert(GATE_EVIDENCE_INTEGRITY.into(), true);
        }
        // Sovereignty: jurisdiction tag must include `AE-` for sovereign-cleared
        // operations OR be a sovereignty-friendly tag.
        if !seal.jurisdiction_tag.starts_with("AE-") && !matches!(seal.jurisdiction_tag.as_str(),
            "NATO-PRU" | "US-DOD-AIEP" | "UK-MOD" | "US-ITAR" | "EU-DUAL-USE")
        {
            faults.insert(GATE_SOVEREIGNTY.into(), true);
        }
        // Air-gap respected: in air-gap mode we refuse seals carrying any
        // `external_egress` flag.
        if self.air_gap {
            let ext = seal
                .sector_extension
                .get("external_egress")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if ext {
                faults.insert(GATE_AIR_GAP_RESPECTED.into(), true);
            }
        }
        faults
    }

    /// Seal an autonomous-logistics step.
    pub fn seal_autonomous_logistics(
        &self,
        input: AutonomousLogistics,
    ) -> SandboxResult<AutonomousLogisticsSeal> {
        let seal = autonomous_logistics::build_seal(
            &input,
            self.institution(),
            self.primary_jurisdiction.seal_tag(),
        )?;
        let mut faults = self.common_faults(&seal);
        if !input.within_odd {
            faults.insert(GATE_ODD_BOUNDARY.into(), true);
        }
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("autonomous logistics step {} blocked by policy", input.mission_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(AutonomousLogisticsSeal {
            seal,
            decision: input.decision,
        })
    }

    /// Seal a sensor-fusion event.
    pub fn seal_sensor_fusion(&self, input: SensorFusion) -> SandboxResult<SensorFusionSeal> {
        let seal = sensor_fusion::build_seal(
            &input,
            self.institution(),
            self.primary_jurisdiction.seal_tag(),
        )?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("sensor fusion event {} blocked by policy", input.track_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(SensorFusionSeal {
            seal,
            classification: input.classification,
        })
    }

    /// Seal an inspection.
    pub fn seal_inspection(&self, input: InspectionQa) -> SandboxResult<InspectionQaSeal> {
        let seal = inspection_qa::build_seal(
            &input,
            self.institution(),
            self.primary_jurisdiction.seal_tag(),
        )?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("inspection lot {} blocked by policy", input.lot_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(InspectionQaSeal {
            seal,
            outcome: input.outcome,
        })
    }

    /// Seal a cyber-defense event.
    pub fn seal_cyber_defense(&self, input: CyberDefenseEvent) -> SandboxResult<CyberDefenseSeal> {
        let seal = cyber_defense::build_seal(
            &input,
            self.institution(),
            self.primary_jurisdiction.seal_tag(),
        )?;
        let faults = self.common_faults(&seal);
        let (decision, _) = self.inner.policy().evaluate(&faults);
        if decision.is_blocked() {
            let gate = faults
                .iter()
                .find(|(_, v)| **v)
                .map(|(k, _)| k.clone())
                .unwrap_or_default();
            return Err(SandboxError::policy(
                gate,
                format!("cyber detection {} blocked by policy", input.detection_id),
            ));
        }
        self.append(seal.clone())?;
        Ok(CyberDefenseSeal {
            seal,
            decision: input.decision,
        })
    }

    /// Mark the next sealed event as classification-boundary tested.
    /// (Convenience for adversarial tests in client code.)
    pub fn check_classification_boundary(&self, payload: &str) -> SandboxResult<()> {
        if has_classified_marker(payload) {
            return Err(SandboxError::policy(
                GATE_CLASSIFICATION_BOUNDARY,
                format!("classified marker detected in '{payload}'"),
            ));
        }
        Ok(())
    }
}

/// Builder for [`DefenseSandbox`].
#[derive(Default)]
pub struct DefenseSandboxBuilder {
    institution: Option<String>,
    primary_jurisdiction: Option<DefenseJurisdiction>,
    extra_gates: Vec<PolicyGate>,
    air_gap: Option<bool>,
    label: Option<String>,
}

impl DefenseSandboxBuilder {
    /// Set institution.
    pub fn institution(mut self, institution: impl Into<String>) -> Self {
        self.institution = Some(institution.into());
        self
    }

    /// Set primary jurisdiction.
    pub fn jurisdiction(mut self, j: DefenseJurisdiction) -> Self {
        self.primary_jurisdiction = Some(j);
        self
    }

    /// Set air-gap mode.
    pub fn air_gap(mut self, on: bool) -> Self {
        self.air_gap = Some(on);
        self
    }

    /// Add an extra policy gate.
    pub fn with_extra_gate(mut self, gate: PolicyGate) -> Self {
        self.extra_gates.push(gate);
        self
    }

    /// Override the label.
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Build.
    pub fn build(self) -> SandboxResult<DefenseSandbox> {
        let institution = self
            .institution
            .ok_or_else(|| SandboxError::config("institution not set"))?;
        let primary = self
            .primary_jurisdiction
            .unwrap_or(DefenseJurisdiction::TawazunUae);
        let mut all_gates = default_gates();
        all_gates.extend(self.extra_gates);
        let label = self
            .label
            .unwrap_or_else(|| format!("{institution} Defense Sandbox"));
        let inner = SandboxBuilder::new(Sector::Defense)
            .crate_name("aethelred-sandbox-defense")
            .crate_version(env!("CARGO_PKG_VERSION"))
            .tenant(&institution)
            .label(&label)
            .jurisdiction(primary.seal_tag())
            .workflow("autonomous_logistics")
            .workflow("sensor_fusion")
            .workflow("inspection_qa")
            .workflow("cyber_defense")
            .with_gates(all_gates)
            .build()?;
        Ok(DefenseSandbox {
            inner,
            primary_jurisdiction: primary,
            air_gap: self.air_gap.unwrap_or(true),
        })
    }
}

fn is_supported_jurisdiction(tag: &str) -> bool {
    matches!(
        tag,
        "AE-TAWAZUN" | "AE-AF" | "NATO-PRU" | "US-DOD-AIEP" | "UK-MOD" | "US-ITAR" | "EU-DUAL-USE"
    )
}

fn has_classified_marker(s: &str) -> bool {
    let upper = s.to_uppercase();
    upper.contains("TS//SCI")
        || upper.contains("SECRET//")
        || upper.contains("CONFIDENTIAL//")
        || upper.contains("CLASSIFICATION:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quickstart_constructs_with_air_gap() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        assert_eq!(sb.institution(), "EDGE");
        assert_eq!(sb.primary_jurisdiction(), DefenseJurisdiction::TawazunUae);
        assert!(sb.is_air_gap());
    }

    #[test]
    fn seal_autonomous_logistics_happy_path() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        let s = sb
            .seal_autonomous_logistics(AutonomousLogistics::demo())
            .unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_sensor_fusion_happy_path() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        let s = sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_inspection_happy_path() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        let s = sb.seal_inspection(InspectionQa::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn seal_cyber_defense_happy_path() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        let s = sb.seal_cyber_defense(CyberDefenseEvent::demo()).unwrap();
        assert!(s.id_string().starts_with("seal_"));
    }

    #[test]
    fn classified_marker_blocks() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        let r = sb.check_classification_boundary("CLASSIFICATION: TS//SCI");
        assert!(r.is_err());
        assert!(r.unwrap_err().is_policy_denial());
    }

    #[test]
    fn export_evidence_returns_appended_seals() {
        let sb = DefenseSandbox::quickstart("EDGE").unwrap();
        sb.seal_autonomous_logistics(AutonomousLogistics::demo()).unwrap();
        sb.seal_sensor_fusion(SensorFusion::demo()).unwrap();
        let bundle = sb.export_evidence().unwrap();
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.sector, Sector::Defense);
    }
}
