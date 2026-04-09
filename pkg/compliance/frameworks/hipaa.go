package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// HIPAA returns the Health Insurance Portability and Accountability Act
// framework definition with controls mapped to Aethelred platform capabilities.
//
// HIPAA establishes national standards for the protection of individually
// identifiable health information (Protected Health Information, or PHI).
// The Security Rule requires covered entities and business associates to
// implement administrative, physical, and technical safeguards for
// electronic PHI (ePHI).
//
// This mapping focuses on the HIPAA Security Rule requirements most
// relevant to AI infrastructure handling healthcare data.
//
// Reference: 45 CFR Parts 160, 162, and 164
func HIPAA() *compliance.Framework {
	return &compliance.Framework{
		ID:          "hipaa",
		Name:        "Health Insurance Portability and Accountability Act",
		Version:     "Security Rule (2013 Omnibus Update)",
		Description: "Federal regulation protecting the security and privacy of individually identifiable health information. The Security Rule establishes administrative, physical, and technical safeguard requirements for electronic PHI.",
		Category:    compliance.FrameworkCategoryHealthcare,
		Authority:   "U.S. Department of Health and Human Services (HHS)",
		EffectiveDate: time.Date(2013, 9, 23, 0, 0, 0, 0, time.UTC),
		Controls:    hipaaControls(),
	}
}

func hipaaControls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// Administrative Safeguards (164.308)
		// -------------------------------------------------------------------
		{
			ID:          "164.308(a)(1)",
			Name:        "Security Management Process",
			Description: "Implement policies and procedures to prevent, detect, contain, and correct security violations. Includes risk analysis, risk management, sanction policy, and information system activity review.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Security management policies and procedures", Source: "governance-module", Automated: false},
				{Type: compliance.EvidenceTypeReport, Description: "Risk analysis and risk management plan", Source: "risk-assessment", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Information system activity review records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRiskAssessment, compliance.CapAuditTrail, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "164.308(a)(3)",
			Name:        "Workforce Security",
			Description: "Implement policies and procedures to ensure that all members of the workforce have appropriate access to electronic PHI and to prevent unauthorized access. Includes authorization and supervision, workforce clearance, and termination procedures.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "RBAC configuration for workforce access controls", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access provisioning and de-provisioning audit trail", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapRBACGovernance, compliance.CapAuditTrail},
		},
		{
			ID:          "164.308(a)(4)",
			Name:        "Information Access Management",
			Description: "Implement policies and procedures for authorizing access to electronic PHI that are consistent with the Privacy Rule. Includes access authorization and access establishment and modification.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Granular access control policies for PHI-containing systems", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access authorization change records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapRBACGovernance, compliance.CapDataClassification},
		},
		{
			ID:          "164.308(a)(5)",
			Name:        "Security Awareness and Training",
			Description: "Implement a security awareness and training program for all members of the workforce including management. Includes security reminders, protection from malicious software, login monitoring, and password management.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Security awareness and training program documentation", Source: "hr-systems", Automated: false},
				{Type: compliance.EvidenceTypeReport, Description: "Training completion records", Source: "hr-systems", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapSecurityTraining},
		},
		{
			ID:          "164.308(a)(6)",
			Name:        "Security Incident Procedures",
			Description: "Implement policies and procedures to address security incidents. Identify and respond to suspected or known security incidents; mitigate, to the extent practicable, harmful effects of security incidents that are known to the covered entity or business associate; and document security incidents and their outcomes.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Security incident response procedures", Source: "incident-response", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Incident detection, response, and resolution records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapAuditTrail, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "164.308(a)(7)",
			Name:        "Contingency Plan",
			Description: "Establish and implement policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI. Includes data backup plan, disaster recovery plan, emergency mode operation plan, testing and revision procedures.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Contingency and disaster recovery plan", Source: "disaster-recovery", Automated: false},
				{Type: compliance.EvidenceTypeTestResult, Description: "DR testing results and backup verification records", Source: "dr-testing", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Backup execution and verification logs", Source: "backup-system", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDisasterRecovery, compliance.CapAuditTrail},
		},
		{
			ID:          "164.308(a)(8)",
			Name:        "Evaluation",
			Description: "Perform a periodic technical and nontechnical evaluation based initially upon the standards implemented under this rule, and subsequently in response to environmental or operational changes affecting the security of ePHI.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Periodic security evaluation reports", Source: "security-assessment", Automated: false},
				{Type: compliance.EvidenceTypeTestResult, Description: "Vulnerability assessment and penetration testing results", Source: "security-testing", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapVulnerabilityMgmt, compliance.CapPenetrationTesting},
		},
		{
			ID:          "164.308(b)(1)",
			Name:        "Business Associate Contracts",
			Description: "A covered entity may permit a business associate to create, receive, maintain, or transmit ePHI on the covered entity's behalf only if the covered entity obtains satisfactory assurances that the business associate will appropriately safeguard the information.",
			Category:    "Administrative Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Business Associate Agreement templates and executed agreements", Source: "legal", Automated: false},
				{Type: compliance.EvidenceTypeAttestation, Description: "On-chain attestation of BA compliance status", Source: "x/seal", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapThirdPartyRisk, compliance.CapDigitalSeal},
		},

		// -------------------------------------------------------------------
		// Technical Safeguards (164.312)
		// -------------------------------------------------------------------
		{
			ID:          "164.312(a)(1)",
			Name:        "Access Control",
			Description: "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to those persons or software programs that have been granted access rights. Includes unique user identification, emergency access procedure, automatic logoff, and encryption and decryption.",
			Category:    "Technical Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Technical access control configuration with unique identifiers", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Authentication and authorization audit records", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Encryption configuration for ePHI at rest", Source: "storage-config", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapEncryptedAtRest, compliance.CapKeyManagement, compliance.CapAuditTrail},
		},
		{
			ID:          "164.312(b)",
			Name:        "Audit Controls",
			Description: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.",
			Category:    "Technical Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "System activity audit logs with tamper-detection (hash chain)", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Audit mechanism configuration showing comprehensiveness", Source: "x/pouw/audit", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapImmutableLedger},
		},
		{
			ID:          "164.312(c)(1)",
			Name:        "Integrity Controls",
			Description: "Implement policies and procedures to protect ePHI from improper alteration or destruction. Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed in an unauthorized manner.",
			Category:    "Technical Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeAttestation, Description: "Cryptographic integrity verification (Digital Seals)", Source: "x/seal", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Data integrity verification records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDigitalSeal, compliance.CapImmutableLedger, compliance.CapAuditTrail},
		},
		{
			ID:          "164.312(d)",
			Name:        "Person or Entity Authentication",
			Description: "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
			Category:    "Technical Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Multi-factor authentication configuration", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "Cryptographic identity certificates", Source: "pqc-crypto", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapPQCCrypto, compliance.CapKeyManagement},
		},
		{
			ID:          "164.312(e)(1)",
			Name:        "Transmission Security",
			Description: "Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network. Implement a mechanism to encrypt ePHI whenever deemed appropriate.",
			Category:    "Technical Safeguards",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "TLS certificates with PQC key exchange configuration", Source: "pqc-crypto", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Transmission encryption configuration", Source: "network-config", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapPQCCrypto},
		},

		// -------------------------------------------------------------------
		// Privacy Rule Controls for AI
		// -------------------------------------------------------------------
		{
			ID:          "164.502(b)",
			Name:        "Minimum Necessary Standard",
			Description: "When using or disclosing PHI or when requesting PHI from another covered entity or business associate, a covered entity or business associate must make reasonable efforts to limit PHI to the minimum necessary to accomplish the intended purpose.",
			Category:    "Privacy Rule",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Data minimization policies in AI pipeline configuration", Source: "data-governance", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Data access scope records showing minimum necessary enforcement", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapPrivacyControls, compliance.CapDataClassification, compliance.CapAccessControl},
		},
	}
}
