package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// CMMC returns the Cybersecurity Maturity Model Certification 2.0 framework
// definition with controls mapped to Aethelred platform capabilities.
//
// CMMC 2.0 is required for organizations in the defense industrial base (DIB)
// that handle Controlled Unclassified Information (CUI) or Federal Contract
// Information (FCI). Level 2 aligns with NIST SP 800-171 requirements, and
// Level 3 adds enhanced controls from NIST SP 800-172.
//
// Reference: 32 CFR Part 170
func CMMC() *compliance.Framework {
	return &compliance.Framework{
		ID:          "cmmc-2.0",
		Name:        "Cybersecurity Maturity Model Certification",
		Version:     "2.0",
		Description: "Department of Defense cybersecurity framework required for defense contractors handling CUI and FCI. Implements NIST SP 800-171 (Level 2) and NIST SP 800-172 (Level 3) requirements with third-party assessment.",
		Category:    compliance.FrameworkCategoryGovernment,
		Authority:   "U.S. Department of Defense (DoD)",
		EffectiveDate: time.Date(2024, 12, 16, 0, 0, 0, 0, time.UTC),
		Controls:    cmmcControls(),
	}
}

func cmmcControls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// Access Control (AC)
		// -------------------------------------------------------------------
		{
			ID:          "AC.L2-3.1.1",
			Name:        "Authorized Access Control",
			Description: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
			Category:    "Access Control",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "RBAC policies and access control lists", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access control enforcement audit logs", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapRBACGovernance, compliance.CapAuditTrail},
		},
		{
			ID:          "AC.L2-3.1.2",
			Name:        "Transaction and Function Control",
			Description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
			Category:    "Access Control",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Function-level access control configuration", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Transaction authorization records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAccessControl, compliance.CapImmutableLedger},
		},
		{
			ID:          "AC.L2-3.1.5",
			Name:        "Least Privilege",
			Description: "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
			Category:    "Access Control",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Least privilege access policies", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Privilege escalation audit records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAccessControl},
		},

		// -------------------------------------------------------------------
		// Audit and Accountability (AU)
		// -------------------------------------------------------------------
		{
			ID:          "AU.L2-3.3.1",
			Name:        "System Auditing",
			Description: "Create and retain system audit logs and records to the extent needed to enable the monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity.",
			Category:    "Audit and Accountability",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Hash-chained audit log records with retention compliance", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Audit logging configuration and retention policies", Source: "x/pouw/audit", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapImmutableLedger, compliance.CapDataRetention},
		},
		{
			ID:          "AU.L2-3.3.2",
			Name:        "User Accountability",
			Description: "Ensure that the actions of individual system users can be uniquely traced to those users, so they can be held accountable for their actions.",
			Category:    "Audit and Accountability",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "User-attributable action logs with cryptographic identity binding", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "User identity binding configuration", Source: "x/pouw/rbac", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapAccessControl, compliance.CapImmutableLedger},
		},

		// -------------------------------------------------------------------
		// Configuration Management (CM)
		// -------------------------------------------------------------------
		{
			ID:          "CM.L2-3.4.1",
			Name:        "System Baselining",
			Description: "Establish and maintain baseline configurations and inventories of organizational systems throughout the respective system development life cycles.",
			Category:    "Configuration Management",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Baseline configuration records on immutable ledger", Source: "x/pouw/params", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Configuration change history with approval records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapChangeManagement, compliance.CapImmutableLedger, compliance.CapAuditTrail},
		},
		{
			ID:          "CM.L2-3.4.2",
			Name:        "Security Configuration Enforcement",
			Description: "Establish and enforce security configuration settings for information technology products employed in organizational systems.",
			Category:    "Configuration Management",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Security configuration baselines and enforcement records", Source: "x/pouw/params", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Configuration drift detection and remediation logs", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapChangeManagement, compliance.CapContinuousMonitoring},
		},

		// -------------------------------------------------------------------
		// Identification and Authentication (IA)
		// -------------------------------------------------------------------
		{
			ID:          "IA.L2-3.5.1",
			Name:        "User Identification",
			Description: "Identify system users, processes acting on behalf of users, and devices.",
			Category:    "Identification and Authentication",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Identity management system configuration", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Authentication event records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapAuditTrail},
		},
		{
			ID:          "IA.L2-3.5.2",
			Name:        "Authentication Mechanisms",
			Description: "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access to organizational systems.",
			Category:    "Identification and Authentication",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Multi-factor authentication configuration", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "Cryptographic authentication certificates", Source: "pqc-crypto", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapPQCCrypto, compliance.CapKeyManagement},
		},

		// -------------------------------------------------------------------
		// Incident Response (IR)
		// -------------------------------------------------------------------
		{
			ID:          "IR.L2-3.6.1",
			Name:        "Incident Handling",
			Description: "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities.",
			Category:    "Incident Response",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Incident response plan and procedures", Source: "incident-response", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Incident detection, escalation, and resolution records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapAuditTrail, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "IR.L2-3.6.2",
			Name:        "Incident Reporting",
			Description: "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization.",
			Category:    "Incident Response",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Incident tracking and reporting records with timestamps", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeReport, Description: "Incident notification records", Source: "incident-response", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// System and Communications Protection (SC)
		// -------------------------------------------------------------------
		{
			ID:          "SC.L2-3.13.1",
			Name:        "Boundary Protection",
			Description: "Monitor, control, and protect communications at the external managed interfaces of the system and at key internal boundaries of the system.",
			Category:    "System and Communications Protection",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Network boundary control configuration", Source: "network-config", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Network traffic monitoring and filtering records", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "SC.L2-3.13.8",
			Name:        "Data in Transit Protection",
			Description: "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards.",
			Category:    "System and Communications Protection",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "TLS certificates and PQC key exchange configuration", Source: "pqc-crypto", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Encryption-in-transit configuration and cipher suite settings", Source: "network-config", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapPQCCrypto},
		},
		{
			ID:          "SC.L2-3.13.16",
			Name:        "Data at Rest Protection",
			Description: "Protect the confidentiality of CUI at rest.",
			Category:    "System and Communications Protection",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Encryption-at-rest configuration with key management details", Source: "storage-config", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "HSM-backed encryption key attestations", Source: "key-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedAtRest, compliance.CapKeyManagement},
		},

		// -------------------------------------------------------------------
		// System and Information Integrity (SI)
		// -------------------------------------------------------------------
		{
			ID:          "SI.L2-3.14.1",
			Name:        "Flaw Remediation",
			Description: "Identify, report, and correct system flaws in a timely manner.",
			Category:    "System and Information Integrity",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Vulnerability scan results and remediation tracking", Source: "vulnerability-mgmt", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Patch management and remediation records", Source: "change-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVulnerabilityMgmt, compliance.CapChangeManagement},
		},
		{
			ID:          "SI.L2-3.14.6",
			Name:        "Security Alerts and Advisories",
			Description: "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
			Category:    "System and Information Integrity",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Security event monitoring and alerting records", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "SIEM/monitoring alerting rules and thresholds", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapIncidentResponse},
		},
	}
}
