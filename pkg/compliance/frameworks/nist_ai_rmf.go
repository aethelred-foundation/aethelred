// Package frameworks contains regulatory framework definitions with control
// mappings to Aethelred platform capabilities.
package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// NISTAIIRMF returns the NIST AI Risk Management Framework 1.0 definition
// with controls mapped to Aethelred platform capabilities.
//
// The NIST AI RMF is a voluntary framework published by the National
// Institute of Standards and Technology that provides guidance for managing
// risks associated with AI systems throughout their lifecycle. It is
// organized around four core functions: Govern, Map, Measure, and Manage.
//
// Reference: https://www.nist.gov/artificial-intelligence/ai-risk-management-framework
func NISTAIIRMF() *compliance.Framework {
	return &compliance.Framework{
		ID:          "nist-ai-rmf",
		Name:        "NIST AI Risk Management Framework",
		Version:     "1.0",
		Description: "Voluntary framework for managing risks in the design, development, use, and evaluation of AI products, services, and systems. Applicable across sectors and organization types.",
		Category:    compliance.FrameworkCategoryAI,
		Authority:   "National Institute of Standards and Technology (NIST)",
		EffectiveDate: time.Date(2023, 1, 26, 0, 0, 0, 0, time.UTC),
		Controls:    nistAIRMFControls(),
	}
}

// nistAIRMFControls returns the full set of NIST AI RMF controls.
func nistAIRMFControls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// GOVERN: Establish and maintain organizational AI governance
		// -------------------------------------------------------------------
		{
			ID:          "GOV-1",
			Name:        "AI Risk Management Policies",
			Description: "Policies, processes, procedures, and practices across the organization related to the mapping, measuring, and managing of AI risks are in place, transparent, and implemented effectively.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Documented AI risk management policy", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "On-chain governance parameter configuration", Source: "x/pouw/params", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Governance proposal and voting records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAuditTrail, compliance.CapChangeManagement},
		},
		{
			ID:          "GOV-2",
			Name:        "Accountability Structures",
			Description: "Accountability structures are in place so that the appropriate teams and individuals are empowered, responsible, and trained for mapping, measuring, and managing AI risks.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "RACI matrix for AI risk management roles", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "RBAC configuration showing role assignments", Source: "x/pouw/rbac", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAccessControl, compliance.CapSecurityTraining},
		},
		{
			ID:          "GOV-3",
			Name:        "Workforce AI Risk Competency",
			Description: "Workforce diversity, equity, inclusion, and accessibility processes are prioritized in the mapping, measuring, and managing of AI risks throughout the lifecycle.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Training program documentation for AI risk management", Source: "hr-systems", Automated: false},
				{Type: compliance.EvidenceTypeReport, Description: "Training completion records", Source: "hr-systems", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapSecurityTraining},
		},
		{
			ID:          "GOV-4",
			Name:        "Organizational AI Risk Tolerance",
			Description: "Organizational teams are committed to a culture that considers and communicates AI risk.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Risk appetite statement for AI systems", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Risk threshold configuration in platform parameters", Source: "x/pouw/params", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapRBACGovernance},
		},
		{
			ID:          "GOV-5",
			Name:        "Third-Party AI Risk",
			Description: "Processes are in place for robust engagement with relevant AI actors to ensure responsible and trustworthy AI in third-party software and services.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Third-party AI vendor assessment procedures", Source: "procurement", Automated: false},
				{Type: compliance.EvidenceTypeReport, Description: "Vendor risk assessment records", Source: "procurement", Automated: false},
				{Type: compliance.EvidenceTypeAttestation, Description: "Digital Seal attestations for third-party model integrity", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapThirdPartyRisk, compliance.CapDigitalSeal, compliance.CapModelProvenance},
		},
		{
			ID:          "GOV-6",
			Name:        "AI Lifecycle Governance",
			Description: "Policies and procedures are in place to address AI risks and benefits arising from third-party software and data are in place.",
			Category:    "Govern",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Model lifecycle event trail from training to deployment", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeAttestation, Description: "Digital Seal chain of custody attestations", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapModelProvenance, compliance.CapDigitalSeal, compliance.CapAuditTrail, compliance.CapImmutableLedger},
		},

		// -------------------------------------------------------------------
		// MAP: Understand AI system context and risk landscape
		// -------------------------------------------------------------------
		{
			ID:          "MAP-1",
			Name:        "AI System Context Identification",
			Description: "Context is established and understood for the AI system, including intended purpose, deployment setting, and potential benefits and costs.",
			Category:    "Map",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "AI system context documentation and intended use specification", Source: "model-registry", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Model metadata registered on-chain", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapModelProvenance, compliance.CapDigitalSeal, compliance.CapDataClassification},
		},
		{
			ID:          "MAP-2",
			Name:        "AI System Categorization",
			Description: "Categorization of the AI system is performed to inform risk assessment and management processes.",
			Category:    "Map",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "AI system risk categorization report", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Risk category assignment in platform configuration", Source: "x/pouw/params", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapDataClassification},
		},
		{
			ID:          "MAP-3",
			Name:        "Benefits and Costs Assessment",
			Description: "AI system benefits and costs are assessed to understand impact and potential for unintended consequences.",
			Category:    "Map",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Impact assessment documentation", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Continuous monitoring metrics for system impact", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapBiasMonitoring, compliance.CapRiskAssessment},
		},
		{
			ID:          "MAP-4",
			Name:        "Risk Identification",
			Description: "Risks and benefits are mapped for all components of the AI system including third-party software and data.",
			Category:    "Map",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Comprehensive risk register for AI system components", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeAttestation, Description: "Supply chain attestations for model components", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapModelProvenance, compliance.CapThirdPartyRisk},
		},

		// -------------------------------------------------------------------
		// MEASURE: Quantify and track AI risks
		// -------------------------------------------------------------------
		{
			ID:          "MEASURE-1",
			Name:        "Risk Metrics and Measurement",
			Description: "Appropriate methods and metrics are identified and applied to measure AI risks and trustworthiness characteristics.",
			Category:    "Measure",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Defined risk metrics and measurement methodology", Source: "monitoring", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Automated metric collection records", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeTestResult, Description: "Bias and fairness test results", Source: "bias-monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapBiasMonitoring, compliance.CapAuditTrail},
		},
		{
			ID:          "MEASURE-2",
			Name:        "AI System Evaluation",
			Description: "AI systems are evaluated for trustworthy characteristics and the measurement approaches include internal and external validation.",
			Category:    "Measure",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeTestResult, Description: "Model validation test results", Source: "x/pouw/verification", Automated: true},
				{Type: compliance.EvidenceTypeAttestation, Description: "TEE attestation of compute integrity during evaluation", Source: "tee-attestation", Automated: true},
				{Type: compliance.EvidenceTypeReport, Description: "Independent evaluation report", Source: "external-auditor", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapVerifiableCompute, compliance.CapTEEAttestation, compliance.CapDigitalSeal, compliance.CapPoUWConsensus},
		},
		{
			ID:          "MEASURE-3",
			Name:        "Continuous Monitoring",
			Description: "Mechanisms for tracking identified AI risks over time are in place.",
			Category:    "Measure",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Continuous risk monitoring logs", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Alerting thresholds and escalation configuration", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapAuditTrail, compliance.CapIncidentResponse},
		},
		{
			ID:          "MEASURE-4",
			Name:        "Measurement Feedback Loops",
			Description: "Feedback about efficacy of measurement is collected and acted upon to improve measurement approaches.",
			Category:    "Measure",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Measurement effectiveness review documentation", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Historical metric trend analysis", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// MANAGE: Respond to and mitigate AI risks
		// -------------------------------------------------------------------
		{
			ID:          "MANAGE-1",
			Name:        "Risk Treatment and Response",
			Description: "AI risks based on assessments and other analytical output from the MAP and MEASURE functions are prioritized, responded to, and managed.",
			Category:    "Manage",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Risk treatment plan with prioritized actions", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Automated enforcement actions (slashing records)", Source: "x/pouw/slashing", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Incident response records", Source: "incident-response", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapSlashingEnforcement, compliance.CapIncidentResponse, compliance.CapRiskAssessment},
		},
		{
			ID:          "MANAGE-2",
			Name:        "Risk Response Strategies",
			Description: "Strategies to maximize AI benefits and minimize negative impacts are planned, prepared, implemented, documented, and informed by input from relevant AI actors.",
			Category:    "Manage",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Documented risk response procedures", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Automated response configuration (circuit breakers, kill switches)", Source: "x/pouw/params", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapHumanOversight, compliance.CapChangeManagement},
		},
		{
			ID:          "MANAGE-3",
			Name:        "Risk Management Communication",
			Description: "Post-deployment AI system monitoring plans are implemented, including mechanisms for capturing and evaluating input from users and other relevant AI actors.",
			Category:    "Manage",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Stakeholder communication plan and records", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "On-chain governance communication records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapRBACGovernance, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "MANAGE-4",
			Name:        "Incident Response and Recovery",
			Description: "Risk treatments, including response and recovery, and communication plans for the identified and measured AI risks are documented and monitored regularly.",
			Category:    "Manage",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "AI incident response and recovery plan", Source: "incident-response", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Incident response execution records with timestamps", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeTestResult, Description: "Disaster recovery test results", Source: "dr-testing", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapDisasterRecovery, compliance.CapAuditTrail},
		},
	}
}
