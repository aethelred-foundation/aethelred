//! Healthcare fixtures library — named, realistic scenarios.

use crate::workflows::ambient_scribe::AmbientNote;
use crate::workflows::claims::{ClaimDecision, ClaimsAdjudication};
use crate::workflows::clinical_ai::ClinicalInference;
use crate::workflows::genomics::{GenomicsDatasetClass, GenomicsInference};
use crate::HealthcareSandbox;
use aethelred_sandbox_core::policy::Decision;
use aethelred_sandbox_core::SandboxResult;

/// One named, runnable healthcare scenario.
#[derive(Debug, Clone)]
pub enum HealthcareFixture {
    /// Genomics scenario.
    Genomics {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Input.
        input: GenomicsInference,
    },
    /// Clinical AI scenario.
    Clinical {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Input.
        input: ClinicalInference,
    },
    /// Ambient scribe scenario.
    Ambient {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Input.
        input: AmbientNote,
    },
    /// Claims scenario.
    Claims {
        /// Stable id.
        id: &'static str,
        /// Description.
        description: &'static str,
        /// Tags.
        tags: Vec<&'static str>,
        /// Expected decision.
        expected: Decision,
        /// Input.
        input: ClaimsAdjudication,
    },
}

impl HealthcareFixture {
    /// Stable id.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Genomics { id, .. }
            | Self::Clinical { id, .. }
            | Self::Ambient { id, .. }
            | Self::Claims { id, .. } => id,
        }
    }
    /// Description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Genomics { description, .. }
            | Self::Clinical { description, .. }
            | Self::Ambient { description, .. }
            | Self::Claims { description, .. } => description,
        }
    }
    /// Tags.
    pub fn tags(&self) -> &[&'static str] {
        match self {
            Self::Genomics { tags, .. }
            | Self::Clinical { tags, .. }
            | Self::Ambient { tags, .. }
            | Self::Claims { tags, .. } => tags,
        }
    }
    /// Expected decision.
    pub fn expected(&self) -> Decision {
        match self {
            Self::Genomics { expected, .. }
            | Self::Clinical { expected, .. }
            | Self::Ambient { expected, .. }
            | Self::Claims { expected, .. } => *expected,
        }
    }

    /// Run against a sandbox.
    pub fn run(&self, sandbox: &HealthcareSandbox) -> SandboxResult<()> {
        let result: SandboxResult<()> = match self {
            Self::Genomics { input, .. } => sandbox
                .seal_genomics_inference(input.clone())
                .map(|_| ()),
            Self::Clinical { input, .. } => sandbox
                .seal_clinical_inference(input.clone())
                .map(|_| ()),
            Self::Ambient { input, .. } => sandbox.seal_ambient_note(input.clone()).map(|_| ()),
            Self::Claims { input, .. } => sandbox.seal_claims_adjudication(input.clone()).map(|_| ()),
        };
        match (self.expected(), result) {
            (Decision::Allow | Decision::ReviewRequired, Ok(_)) => Ok(()),
            (Decision::FailClosed, Err(e)) if e.is_policy_denial() => Ok(()),
            (expected, actual) => Err(aethelred_sandbox_core::SandboxError::Other(format!(
                "fixture `{}` expected {:?}, got {:?}",
                self.id(),
                expected,
                actual
            ))),
        }
    }
}

/// Healthcare fixture catalog.
pub struct HealthcareFixtures;

impl HealthcareFixtures {
    /// Combined catalog.
    pub fn all() -> Vec<HealthcareFixture> {
        let mut v = Vec::new();
        v.extend(Self::happy_path());
        v.extend(Self::regulatory_edge());
        v.extend(Self::adversarial());
        v
    }

    /// Happy paths.
    pub fn happy_path() -> Vec<HealthcareFixture> {
        vec![
            HealthcareFixture::Genomics {
                id: "healthcare.genomics.happy.consented_synthetic",
                description: "Genomics inference on consented + synthetic dataset",
                tags: vec!["happy", "doh", "genomics"],
                expected: Decision::Allow,
                input: GenomicsInference::demo(),
            },
            HealthcareFixture::Clinical {
                id: "healthcare.clinical.happy.radiology",
                description: "Radiology inference with radiologist sign-off",
                tags: vec!["happy", "doh", "clinical"],
                expected: Decision::Allow,
                input: ClinicalInference::demo(),
            },
            HealthcareFixture::Ambient {
                id: "healthcare.ambient.happy.signed_note",
                description: "Ambient scribe note signed by clinician",
                tags: vec!["happy", "doh", "ambient"],
                expected: Decision::Allow,
                input: AmbientNote::demo(),
            },
            HealthcareFixture::Claims {
                id: "healthcare.claims.happy.approved",
                description: "Approved claim, no adverse action",
                tags: vec!["happy", "purehealth", "claims"],
                expected: Decision::Allow,
                input: ClaimsAdjudication::demo(),
            },
        ]
    }

    /// Regulatory-edge.
    pub fn regulatory_edge() -> Vec<HealthcareFixture> {
        let mut adjusted_with_reason = ClaimsAdjudication::demo();
        adjusted_with_reason.decision = ClaimDecision::ApprovedAdjusted;
        adjusted_with_reason.reason_class = Some("network_limit".into());

        let mut research_only = GenomicsInference::demo();
        research_only.dataset_class = GenomicsDatasetClass::ResearchOnly;

        vec![
            HealthcareFixture::Claims {
                id: "healthcare.claims.edge.approved_adjusted_with_reason",
                description: "Adjusted claim with reason class — passes",
                tags: vec!["edge", "purehealth", "claims"],
                expected: Decision::Allow,
                input: adjusted_with_reason,
            },
            HealthcareFixture::Genomics {
                id: "healthcare.genomics.edge.research_only_dataset",
                description: "Research-only dataset — soft-fails to review (optional gate)",
                tags: vec!["edge", "dataset-class", "genomics"],
                expected: Decision::ReviewRequired,
                input: research_only,
            },
        ]
    }

    /// Adversarial.
    pub fn adversarial() -> Vec<HealthcareFixture> {
        let mut email_genomics = GenomicsInference::demo();
        email_genomics.sample_pseudo_id = "patient@example.com".into();

        let mut mrn_clinical = ClinicalInference::demo();
        mrn_clinical.encounter_pseudo_id = "mrn:1234567".into();

        let mut unsigned_ambient = AmbientNote::demo();
        unsigned_ambient.clinician_signed = false;

        let mut denied_no_reason = ClaimsAdjudication::demo();
        denied_no_reason.decision = ClaimDecision::Denied;
        denied_no_reason.reason_class = None;

        let mut ssn_claims = ClaimsAdjudication::demo();
        ssn_claims.member_pseudo_id = "ssn:123-45-6789".into();

        let mut emirates_genomics = GenomicsInference::demo();
        emirates_genomics.sample_pseudo_id = "emirates_id:784-1990-1234567-1".into();

        // (research-only dataset is now in regulatory_edge — it's a soft gate)

        vec![
            HealthcareFixture::Genomics {
                id: "healthcare.genomics.adv.email_in_pseudo_id",
                description: "Email in sample pseudo id — must fail PHI gate",
                tags: vec!["adv", "phi", "genomics"],
                expected: Decision::FailClosed,
                input: email_genomics,
            },
            HealthcareFixture::Genomics {
                id: "healthcare.genomics.adv.emirates_id_in_pseudo_id",
                description: "Emirates ID in sample pseudo id — must fail PHI gate",
                tags: vec!["adv", "phi", "genomics"],
                expected: Decision::FailClosed,
                input: emirates_genomics,
            },
            HealthcareFixture::Clinical {
                id: "healthcare.clinical.adv.mrn_marker",
                description: "MRN in encounter id — must fail PHI gate",
                tags: vec!["adv", "phi", "clinical"],
                expected: Decision::FailClosed,
                input: mrn_clinical,
            },
            HealthcareFixture::Ambient {
                id: "healthcare.ambient.adv.unsigned",
                description: "Unsigned ambient note — must fail clinical-review gate",
                tags: vec!["adv", "clinical-review", "ambient"],
                expected: Decision::FailClosed,
                input: unsigned_ambient,
            },
            HealthcareFixture::Claims {
                id: "healthcare.claims.adv.denied_without_reason",
                description: "Denied claim without reason class — must hard-block",
                tags: vec!["adv", "explainability", "claims"],
                expected: Decision::FailClosed,
                input: denied_no_reason,
            },
            HealthcareFixture::Claims {
                id: "healthcare.claims.adv.ssn_in_pseudo_id",
                description: "SSN in member pseudo id — must fail PHI gate",
                tags: vec!["adv", "phi", "claims"],
                expected: Decision::FailClosed,
                input: ssn_claims,
            },
        ]
    }

    /// Subset filtered by tag.
    pub fn by_tag(tag: &str) -> Vec<HealthcareFixture> {
        Self::all()
            .into_iter()
            .filter(|f| f.tags().contains(&tag))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_succeeds() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        for f in HealthcareFixtures::happy_path() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn adversarial_blocks() {
        let sb = HealthcareSandbox::quickstart("M42").unwrap();
        for f in HealthcareFixtures::adversarial() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn regulatory_edge_runs() {
        let sb = HealthcareSandbox::quickstart("PureHealth").unwrap();
        for f in HealthcareFixtures::regulatory_edge() {
            f.run(&sb).unwrap_or_else(|e| panic!("{}: {e}", f.id()));
        }
    }

    #[test]
    fn unique_ids() {
        let ids: Vec<&str> = HealthcareFixtures::all().iter().map(|f| f.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), n);
    }

    #[test]
    fn ids_are_namespaced() {
        for f in HealthcareFixtures::all() {
            assert!(f.id().starts_with("healthcare."));
        }
    }

    #[test]
    fn at_least_six_adversarial() {
        assert!(HealthcareFixtures::adversarial().len() >= 6);
    }

    #[test]
    fn by_tag_phi_returns_subset() {
        let phi = HealthcareFixtures::by_tag("phi");
        assert!(phi.len() >= 3);
    }
}
