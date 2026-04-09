package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// EUAIAct returns the EU Artificial Intelligence Act framework definition
// with controls mapped to Aethelred platform capabilities.
//
// The EU AI Act is the world's first comprehensive legal framework for AI,
// establishing a risk-based approach to AI regulation. It classifies AI
// systems into risk categories and imposes obligations proportional to
// the level of risk. High-risk AI systems face the most stringent
// requirements including conformity assessment, technical documentation,
// transparency, and human oversight.
//
// This mapping focuses on obligations for providers and deployers of
// high-risk AI systems, which represent the primary use case for
// regulated enterprise AI infrastructure.
//
// Reference: Regulation (EU) 2024/1689
func EUAIAct() *compliance.Framework {
	return &compliance.Framework{
		ID:          "eu-ai-act",
		Name:        "EU Artificial Intelligence Act",
		Version:     "2024/1689",
		Description: "Comprehensive EU regulation establishing harmonized rules on artificial intelligence. Implements a risk-based classification system with graduated obligations for AI system providers, deployers, importers, and distributors.",
		Category:    compliance.FrameworkCategoryAI,
		Authority:   "European Parliament and Council of the European Union",
		EffectiveDate: time.Date(2024, 8, 1, 0, 0, 0, 0, time.UTC),
		Controls:    euAIActControls(),
	}
}

// euAIActControls returns the full set of EU AI Act controls.
func euAIActControls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// Risk Classification (Title II, Chapter 1)
		// -------------------------------------------------------------------
		{
			ID:          "AIA-6",
			Name:        "Classification Rules for High-Risk AI Systems",
			Description: "AI systems shall be classified as high-risk based on their intended purpose and the specific conditions under which they are placed on the market or put into service. Systems used as safety components, or systems in Annex III areas (biometric identification, critical infrastructure, education, employment, essential services, law enforcement, migration, justice) are classified as high-risk.",
			Category:    "Risk Classification",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "AI system risk classification assessment documenting intended purpose and applicable Annex III categories", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Risk classification metadata registered on-chain with model provenance records", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapModelProvenance, compliance.CapDataClassification},
		},

		// -------------------------------------------------------------------
		// Requirements for High-Risk AI (Title III, Chapter 2)
		// -------------------------------------------------------------------
		{
			ID:          "AIA-9",
			Name:        "Risk Management System",
			Description: "A risk management system shall be established, implemented, documented, and maintained in relation to high-risk AI systems. The system shall be a continuous iterative process planned and run throughout the entire lifecycle of the AI system, requiring regular systematic updating.",
			Category:    "Risk Management",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Documented risk management system with lifecycle coverage", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Risk management activity records throughout AI lifecycle", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeReport, Description: "Periodic risk re-assessment reports", Source: "risk-assessment", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapAuditTrail, compliance.CapContinuousMonitoring, compliance.CapModelProvenance},
		},
		{
			ID:          "AIA-10",
			Name:        "Data and Data Governance",
			Description: "High-risk AI systems which make use of techniques involving the training of AI models with data shall be developed on the basis of training, validation and testing data sets that meet quality criteria. Data governance and management practices shall address data collection, design choices, data preparation, relevant assumptions, prior assessment of availability and suitability, bias examination, and identification of data gaps.",
			Category:    "Data Governance",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Data governance policy covering collection, preparation, and quality criteria", Source: "data-governance", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Data provenance records tracking training data lineage", Source: "model-registry", Automated: true},
				{Type: compliance.EvidenceTypeTestResult, Description: "Data quality and bias assessment results", Source: "bias-monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapModelProvenance, compliance.CapBiasMonitoring, compliance.CapDataClassification, compliance.CapAuditTrail},
		},
		{
			ID:          "AIA-11",
			Name:        "Technical Documentation",
			Description: "The technical documentation of a high-risk AI system shall be drawn up before that system is placed on the market or put into service and shall be kept up to date. It shall demonstrate compliance with the requirements set out in this chapter and provide national competent authorities and notified bodies with all the necessary information to assess compliance.",
			Category:    "Documentation",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Technical documentation per Annex IV requirements", Source: "documentation", Automated: false},
				{Type: compliance.EvidenceTypeAttestation, Description: "Digital Seal attestations documenting model architecture and training methodology", Source: "x/seal", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "On-chain model metadata and version history", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDigitalSeal, compliance.CapModelProvenance, compliance.CapAuditTrail, compliance.CapImmutableLedger},
		},
		{
			ID:          "AIA-12",
			Name:        "Record-Keeping and Logging",
			Description: "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system. The logging capabilities shall enable the monitoring of the operation of the high-risk AI system with respect to the occurrence of situations that may result in risks, facilitate post-market monitoring, and enable traceability.",
			Category:    "Logging",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Automated event logging records with hash-chain integrity", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Logging configuration showing retention policies and integrity mechanisms", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeAttestation, Description: "Audit log chain verification attestations", Source: "x/pouw/audit", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapImmutableLedger, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "AIA-13",
			Name:        "Transparency and Information to Deployers",
			Description: "High-risk AI systems shall be designed and developed in such a way to ensure that their operation is sufficiently transparent to enable deployers to interpret the system output and use it appropriately. Instructions for use shall include information on the system's capabilities and limitations, intended purpose, level of accuracy and robustness, and known or foreseeable risks.",
			Category:    "Transparency",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Instructions for use documentation meeting Annex IV transparency requirements", Source: "documentation", Automated: false},
				{Type: compliance.EvidenceTypeTestResult, Description: "Model explainability test results and interpretability metrics", Source: "explainability", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapExplainability, compliance.CapModelProvenance, compliance.CapDigitalSeal},
		},
		{
			ID:          "AIA-14",
			Name:        "Human Oversight",
			Description: "High-risk AI systems shall be designed and developed in such a way, including with appropriate human-machine interface tools, that they can be effectively overseen by natural persons during the period in which they are in use. Human oversight shall aim to prevent or minimize risks to health, safety or fundamental rights that may emerge.",
			Category:    "Human Oversight",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Human oversight workflow configuration with escalation paths", Source: "governance-module", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Human review and override action records", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypePolicy, Description: "Human oversight procedures and intervention protocols", Source: "governance-module", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapHumanOversight, compliance.CapRBACGovernance, compliance.CapAuditTrail},
		},
		{
			ID:          "AIA-15",
			Name:        "Accuracy, Robustness, and Cybersecurity",
			Description: "High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity, and that they perform consistently in those respects throughout their lifecycle. Appropriate measures shall be taken to address the cybersecurity of the system.",
			Category:    "Accuracy and Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeTestResult, Description: "Model accuracy benchmarks and robustness testing results", Source: "x/pouw/verification", Automated: true},
				{Type: compliance.EvidenceTypeAttestation, Description: "TEE attestation of compute integrity during inference", Source: "tee-attestation", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "PQC cryptographic implementation certificates", Source: "pqc-crypto", Automated: true},
				{Type: compliance.EvidenceTypeTestResult, Description: "Penetration testing and vulnerability assessment results", Source: "security-testing", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapTEEAttestation, compliance.CapPQCCrypto, compliance.CapVerifiableCompute, compliance.CapVulnerabilityMgmt, compliance.CapEncryptedTransit, compliance.CapEncryptedAtRest},
		},

		// -------------------------------------------------------------------
		// Conformity Assessment (Title III, Chapter 3)
		// -------------------------------------------------------------------
		{
			ID:          "AIA-43",
			Name:        "Conformity Assessment",
			Description: "Providers of high-risk AI systems shall ensure that the conformity assessment procedure is carried out prior to placing the system on the market or putting it into service. The conformity assessment shall address the quality management system and the technical documentation.",
			Category:    "Conformity Assessment",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "Conformity assessment certificate or declaration of conformity", Source: "conformity-assessment", Automated: false},
				{Type: compliance.EvidenceTypeReport, Description: "Quality management system documentation", Source: "quality-management", Automated: false},
				{Type: compliance.EvidenceTypeAttestation, Description: "Digital Seal attestation of assessed model version", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDigitalSeal, compliance.CapModelProvenance, compliance.CapAuditTrail},
		},
		{
			ID:          "AIA-47",
			Name:        "EU Declaration of Conformity",
			Description: "The provider shall draw up an EU declaration of conformity for each high-risk AI system and keep it at the disposal of the national competent authorities for 10 years after the AI system has been placed on the market or put into service.",
			Category:    "Conformity Assessment",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "EU Declaration of Conformity document", Source: "conformity-assessment", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Immutable ledger record of declaration timestamp and content hash", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapImmutableLedger, compliance.CapDigitalSeal, compliance.CapDataRetention},
		},

		// -------------------------------------------------------------------
		// Obligations of Providers (Title III, Chapter 3)
		// -------------------------------------------------------------------
		{
			ID:          "AIA-16",
			Name:        "Provider Quality Management System",
			Description: "Providers of high-risk AI systems shall put a quality management system in place that ensures compliance with this Regulation. The quality management system shall be documented in a systematic and orderly manner in the form of written policies, procedures, and instructions.",
			Category:    "Provider Obligations",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Quality management system documentation", Source: "quality-management", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Quality process execution records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapChangeManagement, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "AIA-17",
			Name:        "Provider Post-Market Monitoring",
			Description: "Providers shall establish and document a post-market monitoring system in a manner that is proportionate to the nature of the AI technologies and the risks of the high-risk AI system.",
			Category:    "Provider Obligations",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Post-market monitoring plan", Source: "monitoring", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Continuous monitoring data and anomaly detection records", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeReport, Description: "Periodic monitoring review reports", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapAuditTrail, compliance.CapIncidentResponse},
		},
		{
			ID:          "AIA-20",
			Name:        "Corrective Actions",
			Description: "Providers of high-risk AI systems which consider or have reason to consider that a high-risk AI system which they have placed on the market or put into service is not in conformity shall immediately take the necessary corrective actions to bring that system into conformity, to withdraw it, or to recall it.",
			Category:    "Provider Obligations",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Corrective action records with timeline and verification", Source: "incident-response", Automated: true},
				{Type: compliance.EvidenceTypePolicy, Description: "Corrective action procedures", Source: "quality-management", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapChangeManagement, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Deployer Obligations (Title III, Chapter 3)
		// -------------------------------------------------------------------
		{
			ID:          "AIA-26",
			Name:        "Deployer Obligations",
			Description: "Deployers of high-risk AI systems shall use such systems in accordance with the instructions of use accompanying the systems. Deployers shall assign human oversight to natural persons who have the necessary competence, training and authority.",
			Category:    "Deployer Obligations",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Deployment configuration aligned with provider instructions", Source: "deployment-config", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Human oversight assignment and activity records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapHumanOversight, compliance.CapRBACGovernance, compliance.CapAuditTrail, compliance.CapAccessControl},
		},
		{
			ID:          "AIA-27",
			Name:        "Fundamental Rights Impact Assessment",
			Description: "Before putting a high-risk AI system into use, deployers shall carry out an assessment of the impact on fundamental rights that the use of such system may produce.",
			Category:    "Deployer Obligations",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Fundamental rights impact assessment", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeTestResult, Description: "Bias and discrimination testing results", Source: "bias-monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapBiasMonitoring, compliance.CapRiskAssessment, compliance.CapExplainability},
		},
	}
}
