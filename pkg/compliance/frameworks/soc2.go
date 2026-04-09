package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// SOC2 returns the SOC 2 Type II framework definition with controls mapped
// to Aethelred platform capabilities.
//
// SOC 2 Type II is an auditing standard developed by the AICPA that
// evaluates the design and operating effectiveness of controls relevant
// to the Trust Services Criteria: Security, Availability, Processing
// Integrity, Confidentiality, and Privacy. Type II assessments cover
// a period of operation (typically 6-12 months) rather than a point
// in time.
//
// Reference: AICPA Trust Services Criteria (2017)
func SOC2() *compliance.Framework {
	return &compliance.Framework{
		ID:          "soc2",
		Name:        "SOC 2 Type II",
		Version:     "Trust Services Criteria (2017)",
		Description: "AICPA auditing standard evaluating the design and operating effectiveness of controls over a period of time. Covers Security, Availability, Processing Integrity, Confidentiality, and Privacy trust service criteria.",
		Category:    compliance.FrameworkCategorySecurity,
		Authority:   "American Institute of Certified Public Accountants (AICPA)",
		EffectiveDate: time.Date(2018, 4, 15, 0, 0, 0, 0, time.UTC),
		Controls:    soc2Controls(),
	}
}

func soc2Controls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// Security (Common Criteria)
		// -------------------------------------------------------------------
		{
			ID:          "CC6.1",
			Name:        "Logical and Physical Access Controls",
			Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events. This includes identification and authentication, access authorization, and account management.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "RBAC and access control configuration", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access control event audit logs over the audit period", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Account lifecycle management configuration", Source: "x/pouw/rbac", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapRBACGovernance, compliance.CapAuditTrail, compliance.CapKeyManagement},
		},
		{
			ID:          "CC6.2",
			Name:        "User Authentication",
			Description: "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users. For those users whose access is no longer required, credentials are removed.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "User registration, credential issuance, and revocation records", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Authentication mechanism configuration (MFA, certificates)", Source: "x/pouw/rbac", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapPQCCrypto, compliance.CapKeyManagement},
		},
		{
			ID:          "CC6.3",
			Name:        "Authorized Access Enforcement",
			Description: "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles, responsibilities, or the system design and changes, giving consideration to the concepts of least privilege and segregation of duties.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Role-based access control with least privilege policies", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access modification audit records over the period", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAccessControl, compliance.CapAuditTrail},
		},
		{
			ID:          "CC6.6",
			Name:        "System Boundary Security",
			Description: "The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Network security and boundary control configuration", Source: "network-config", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "TLS and encryption certificates", Source: "pqc-crypto", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapPQCCrypto, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "CC6.7",
			Name:        "Data Transmission Protection",
			Description: "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes, and protects it during transmission, movement, or removal to meet the entity's objectives.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "Encryption-in-transit configuration with PQC support", Source: "pqc-crypto", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Data transfer audit records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapPQCCrypto, compliance.CapAuditTrail},
		},
		{
			ID:          "CC7.1",
			Name:        "Vulnerability Management",
			Description: "To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Vulnerability scan results and remediation tracking", Source: "vulnerability-mgmt", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Configuration change monitoring records", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVulnerabilityMgmt, compliance.CapContinuousMonitoring, compliance.CapChangeManagement},
		},
		{
			ID:          "CC7.2",
			Name:        "Security Event Monitoring",
			Description: "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Security event monitoring logs over the audit period", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Anomaly detection and alerting configuration", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapAuditTrail, compliance.CapIncidentResponse},
		},
		{
			ID:          "CC7.3",
			Name:        "Security Incident Response",
			Description: "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives (security incidents) and, if so, takes actions to prevent or address such failures.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Incident response plan and procedures", Source: "incident-response", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Incident response records with timelines", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapAuditTrail, compliance.CapSlashingEnforcement},
		},
		{
			ID:          "CC8.1",
			Name:        "Change Management",
			Description: "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
			Category:    "Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "On-chain governance proposal and approval records for changes", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Change management workflow configuration", Source: "governance-module", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapChangeManagement, compliance.CapRBACGovernance, compliance.CapAuditTrail, compliance.CapImmutableLedger},
		},

		// -------------------------------------------------------------------
		// Availability
		// -------------------------------------------------------------------
		{
			ID:          "A1.1",
			Name:        "Capacity Management",
			Description: "The entity maintains, monitors, and evaluates current processing capacity and use of system components to manage capacity demand and to enable the implementation of additional capacity to help meet its objectives.",
			Category:    "Availability",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Capacity monitoring metrics and trend data", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Auto-scaling and capacity planning configuration", Source: "infrastructure", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring},
		},
		{
			ID:          "A1.2",
			Name:        "Recovery Planning",
			Description: "The entity authorizes, designs, develops or acquires, implements, operates, approves, maintains, and monitors environmental protections, software, data backup processes, and recovery infrastructure to meet its objectives.",
			Category:    "Availability",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Business continuity and disaster recovery plans", Source: "disaster-recovery", Automated: false},
				{Type: compliance.EvidenceTypeTestResult, Description: "DR test results and recovery time metrics", Source: "dr-testing", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapDisasterRecovery},
		},

		// -------------------------------------------------------------------
		// Processing Integrity
		// -------------------------------------------------------------------
		{
			ID:          "PI1.1",
			Name:        "Processing Accuracy and Completeness",
			Description: "The entity implements policies and procedures over system processing to result in products, services, and reporting to meet the entity's objectives.",
			Category:    "Processing Integrity",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeAttestation, Description: "Verifiable compute attestations (TEE + Digital Seal)", Source: "x/seal", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Processing validation and consensus records", Source: "x/pouw/verification", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVerifiableCompute, compliance.CapTEEAttestation, compliance.CapDigitalSeal, compliance.CapPoUWConsensus},
		},
		{
			ID:          "PI1.2",
			Name:        "Processing Input Validation",
			Description: "The entity implements policies and procedures over system inputs that result in products, services, and reporting to meet the entity's objectives.",
			Category:    "Processing Integrity",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Input validation rules and schema enforcement configuration", Source: "x/pouw/params", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Input validation event records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVerifiableCompute, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Confidentiality
		// -------------------------------------------------------------------
		{
			ID:          "C1.1",
			Name:        "Confidential Information Protection",
			Description: "The entity identifies and maintains confidential information to meet the entity's objectives related to confidentiality.",
			Category:    "Confidentiality",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Data classification policies and encryption configuration", Source: "data-governance", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "Encryption key management and HSM attestations", Source: "key-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDataClassification, compliance.CapEncryptedAtRest, compliance.CapEncryptedTransit, compliance.CapKeyManagement},
		},
		{
			ID:          "C1.2",
			Name:        "Confidential Information Disposal",
			Description: "The entity disposes of confidential information to meet the entity's objectives related to confidentiality.",
			Category:    "Confidentiality",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Data retention and secure deletion policies", Source: "data-governance", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Data disposal verification records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapDataRetention, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Privacy
		// -------------------------------------------------------------------
		{
			ID:          "P1.1",
			Name:        "Privacy Notice",
			Description: "The entity provides notice to data subjects about its privacy practices to meet the entity's objectives related to privacy.",
			Category:    "Privacy",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Privacy notice and data processing disclosures", Source: "legal", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Privacy notice acknowledgment records", Source: "consent-mgmt", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapPrivacyControls, compliance.CapConsentManagement},
		},
		{
			ID:          "P3.1",
			Name:        "Personal Information Collection",
			Description: "Personal information is collected consistent with the entity's objectives related to privacy.",
			Category:    "Privacy",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Consent collection and data minimization records", Source: "consent-mgmt", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Data collection scope configuration", Source: "data-governance", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapConsentManagement, compliance.CapPrivacyControls, compliance.CapDataClassification},
		},
		{
			ID:          "P6.1",
			Name:        "Data Quality and Accuracy",
			Description: "The entity collects and maintains accurate, up-to-date, complete, and relevant personal information to meet the entity's objectives related to privacy.",
			Category:    "Privacy",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Data quality validation and correction records", Source: "data-governance", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Data quality rules and validation configuration", Source: "data-governance", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapPrivacyControls, compliance.CapAuditTrail},
		},
	}
}
