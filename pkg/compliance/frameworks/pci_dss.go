package frameworks

import (
	"time"

	"github.com/aethelred/aethelred/pkg/compliance"
)

// PCIDSS returns the PCI Data Security Standard v4.0 framework definition
// with controls mapped to Aethelred platform capabilities.
//
// PCI DSS applies to all entities that store, process, or transmit
// cardholder data and/or sensitive authentication data. For AI systems
// operating in financial services, PCI DSS compliance ensures that
// payment card data is protected throughout the AI processing pipeline.
//
// Reference: PCI DSS v4.0 (March 2022)
func PCIDSS() *compliance.Framework {
	return &compliance.Framework{
		ID:          "pci-dss",
		Name:        "PCI Data Security Standard",
		Version:     "4.0",
		Description: "Global security standard for entities that store, process, or transmit payment card data. Establishes baseline technical and operational requirements for protecting account data throughout the payment ecosystem.",
		Category:    compliance.FrameworkCategoryFinancial,
		Authority:   "Payment Card Industry Security Standards Council (PCI SSC)",
		EffectiveDate: time.Date(2022, 3, 31, 0, 0, 0, 0, time.UTC),
		Controls:    pciDSSControls(),
	}
}

func pciDSSControls() []compliance.Control {
	return []compliance.Control{
		// -------------------------------------------------------------------
		// Requirement 1: Network Security Controls
		// -------------------------------------------------------------------
		{
			ID:          "PCI-1.2",
			Name:        "Network Security Controls Configuration",
			Description: "Network security controls (NSCs) are configured and maintained to restrict inbound and outbound network traffic to/from the cardholder data environment. All connections and traffic flows between trusted and untrusted networks are controlled.",
			Category:    "Network Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Network segmentation and firewall configuration", Source: "network-config", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Network traffic monitoring and filtering logs", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapContinuousMonitoring},
		},

		// -------------------------------------------------------------------
		// Requirement 3: Protect Stored Account Data
		// -------------------------------------------------------------------
		{
			ID:          "PCI-3.5",
			Name:        "Primary Account Number Protection",
			Description: "Primary account number (PAN) is secured wherever it is stored. Strong cryptography is used to render PAN unreadable anywhere it is stored, including on portable digital media, backup media, and in logs.",
			Category:    "Data Protection",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Encryption-at-rest configuration for stored data", Source: "storage-config", Automated: true},
				{Type: compliance.EvidenceTypeCertificate, Description: "HSM key management attestation", Source: "key-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedAtRest, compliance.CapKeyManagement, compliance.CapPQCCrypto},
		},

		// -------------------------------------------------------------------
		// Requirement 4: Protect Data in Transit
		// -------------------------------------------------------------------
		{
			ID:          "PCI-4.2",
			Name:        "Strong Cryptography for Data in Transit",
			Description: "PAN is protected with strong cryptography during transmission over open, public networks. Strong cryptography with appropriate key-management processes is implemented whenever cardholder data is transmitted over networks that are easily accessed by malicious individuals.",
			Category:    "Transmission Security",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeCertificate, Description: "TLS 1.3 certificates with post-quantum key exchange", Source: "pqc-crypto", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Cipher suite configuration and protocol version enforcement", Source: "network-config", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapEncryptedTransit, compliance.CapPQCCrypto},
		},

		// -------------------------------------------------------------------
		// Requirement 6: Develop Secure Systems and Software
		// -------------------------------------------------------------------
		{
			ID:          "PCI-6.3",
			Name:        "Vulnerability Management",
			Description: "Security vulnerabilities are identified and addressed. Vulnerabilities are identified through a combination of vulnerability scanning, code reviews, and penetration testing, and addressed in a timely manner based on risk.",
			Category:    "Secure Development",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Vulnerability scan and penetration test results", Source: "vulnerability-mgmt", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Vulnerability remediation tracking records", Source: "change-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVulnerabilityMgmt, compliance.CapPenetrationTesting, compliance.CapChangeManagement},
		},
		{
			ID:          "PCI-6.5",
			Name:        "Change Management for System Components",
			Description: "Changes to all system components in the production environment are managed in accordance with established change management processes. All changes are documented, authorized, tested, and approved before deployment.",
			Category:    "Secure Development",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "On-chain governance change approval records", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Change management workflow configuration", Source: "governance-module", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapChangeManagement, compliance.CapRBACGovernance, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Requirement 7: Restrict Access to System Components
		// -------------------------------------------------------------------
		{
			ID:          "PCI-7.2",
			Name:        "Access Control Model",
			Description: "Access to system components and data is appropriately defined and assigned. An access control model is defined and includes granting access based on individual personnel job classification and function, with least privileges necessary for the job responsibility.",
			Category:    "Access Control",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "RBAC model with role definitions and access matrices", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Access provisioning and review records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapRBACGovernance, compliance.CapAccessControl, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Requirement 8: Identify Users and Authenticate Access
		// -------------------------------------------------------------------
		{
			ID:          "PCI-8.3",
			Name:        "Strong Authentication for Users and Administrators",
			Description: "Strong authentication for users and administrators is established and managed. Multi-factor authentication (MFA) is implemented for all access into the cardholder data environment.",
			Category:    "Authentication",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "MFA configuration and enforcement policies", Source: "x/pouw/rbac", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Authentication event logs over the assessment period", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAccessControl, compliance.CapPQCCrypto, compliance.CapKeyManagement},
		},
		{
			ID:          "PCI-8.6",
			Name:        "Application and System Account Management",
			Description: "Use of application and system accounts and associated authentication factors is strictly managed. Interactive login for application and system accounts is restricted.",
			Category:    "Authentication",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeConfiguration, Description: "Service account and API key management configuration", Source: "key-management", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Service account usage audit records", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapKeyManagement, compliance.CapAccessControl, compliance.CapAuditTrail},
		},

		// -------------------------------------------------------------------
		// Requirement 10: Log and Monitor All Access
		// -------------------------------------------------------------------
		{
			ID:          "PCI-10.2",
			Name:        "Audit Log Implementation",
			Description: "Audit logs are implemented to support the detection of anomalies and suspicious activity, and the forensic analysis of events. Automated audit trails are implemented for all system components to reconstruct user activities, exceptions, and security events.",
			Category:    "Logging and Monitoring",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Hash-chained audit logs with comprehensive event coverage", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Audit logging configuration showing event types captured", Source: "x/pouw/audit", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapImmutableLedger},
		},
		{
			ID:          "PCI-10.4",
			Name:        "Audit Log Review",
			Description: "Audit logs are reviewed to identify anomalies or suspicious activity. Automated mechanisms are used to perform audit log reviews. Exceptions and anomalies identified during the review process are addressed.",
			Category:    "Logging and Monitoring",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeLog, Description: "Log review records and anomaly investigation documentation", Source: "monitoring", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Automated log analysis and alerting configuration", Source: "monitoring", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapContinuousMonitoring, compliance.CapAuditTrail, compliance.CapIncidentResponse},
		},
		{
			ID:          "PCI-10.5",
			Name:        "Audit Log Integrity",
			Description: "Audit log history is retained and available for analysis. Audit logs are protected from modification and destruction using cryptographic integrity mechanisms.",
			Category:    "Logging and Monitoring",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeAttestation, Description: "Audit log hash chain integrity verification", Source: "x/pouw/audit", Automated: true},
				{Type: compliance.EvidenceTypeConfiguration, Description: "Log retention and immutability configuration", Source: "audit-trail", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapAuditTrail, compliance.CapImmutableLedger, compliance.CapDataRetention},
		},

		// -------------------------------------------------------------------
		// Requirement 11: Test Security of Systems and Networks
		// -------------------------------------------------------------------
		{
			ID:          "PCI-11.3",
			Name:        "Vulnerability Scanning",
			Description: "External and internal vulnerabilities are regularly identified, prioritized, and addressed. Internal and external vulnerability scans are performed at least quarterly and after any significant change.",
			Category:    "Security Testing",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Quarterly vulnerability scan results", Source: "vulnerability-mgmt", Automated: true},
				{Type: compliance.EvidenceTypeLog, Description: "Vulnerability remediation tracking records", Source: "change-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapVulnerabilityMgmt, compliance.CapContinuousMonitoring},
		},
		{
			ID:          "PCI-11.4",
			Name:        "Penetration Testing",
			Description: "External and internal penetration testing is regularly performed and exploitable vulnerabilities and security weaknesses are corrected. Penetration testing covers the entire CDE perimeter and critical systems.",
			Category:    "Security Testing",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypeReport, Description: "Annual penetration testing reports", Source: "security-testing", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Finding remediation records", Source: "change-management", Automated: true},
			},
			AethelredCapabilities: []string{compliance.CapPenetrationTesting, compliance.CapVulnerabilityMgmt},
		},

		// -------------------------------------------------------------------
		// Requirement 12: Organizational Policies and Programs
		// -------------------------------------------------------------------
		{
			ID:          "PCI-12.10",
			Name:        "Incident Response Plan",
			Description: "Suspected and confirmed security incidents that could impact the CDE are responded to immediately. An incident response plan exists, is maintained, and is activated when necessary. Personnel are trained on incident response procedures.",
			Category:    "Organizational",
			EvidenceRequirements: []compliance.EvidenceRequirement{
				{Type: compliance.EvidenceTypePolicy, Description: "Incident response plan documentation", Source: "incident-response", Automated: false},
				{Type: compliance.EvidenceTypeLog, Description: "Incident response execution records", Source: "audit-trail", Automated: true},
				{Type: compliance.EvidenceTypeTestResult, Description: "Annual IR plan testing results", Source: "incident-response", Automated: false},
			},
			AethelredCapabilities: []string{compliance.CapIncidentResponse, compliance.CapAuditTrail, compliance.CapSecurityTraining},
		},
	}
}
