// Package procurement provides pre-built response templates for security
// questionnaires, RFP/RFI responses, and vendor assessment forms. These
// templates reference Aethelred platform capabilities and compliance
// posture to accelerate enterprise procurement cycles.
package procurement

// ---------------------------------------------------------------------------
// Security questionnaire
// ---------------------------------------------------------------------------

// SecurityQuestion represents a single question from a security
// questionnaire with a pre-built response referencing platform capabilities.
type SecurityQuestion struct {
	// ID is the question identifier.
	ID string `json:"id"`

	// Category groups related questions (e.g., "Encryption", "Access Control").
	Category string `json:"category"`

	// Question is the text of the security question.
	Question string `json:"question"`

	// Response is the pre-built answer referencing Aethelred capabilities.
	Response string `json:"response"`

	// Capabilities lists the platform capabilities backing the response.
	Capabilities []string `json:"capabilities"`
}

// SecurityQuestionnaire is a collection of pre-answered security questions
// organized by category for rapid procurement response.
type SecurityQuestionnaire struct {
	// Name identifies this questionnaire template.
	Name string `json:"name"`

	// Description provides context for when to use this template.
	Description string `json:"description"`

	// Questions contains the pre-answered security questions.
	Questions []SecurityQuestion `json:"questions"`
}

// StandardSecurityQuestionnaire returns a comprehensive security
// questionnaire template with pre-built responses for common enterprise
// security questions.
func StandardSecurityQuestionnaire() *SecurityQuestionnaire {
	return &SecurityQuestionnaire{
		Name:        "Standard Enterprise Security Questionnaire",
		Description: "Pre-built responses for common security questionnaire topics including encryption, access control, audit logging, incident response, and compliance. Suitable for SIG Lite, CAIQ, and custom vendor assessments.",
		Questions:   standardQuestions(),
	}
}

func standardQuestions() []SecurityQuestion {
	return []SecurityQuestion{
		// Encryption
		{
			ID:       "SEC-ENC-001",
			Category: "Encryption",
			Question: "Does the platform encrypt data at rest? Describe the encryption algorithm, key length, and key management approach.",
			Response: "All data at rest is encrypted using AES-256-GCM with keys managed through Hardware Security Modules (HSMs). Key rotation is automated on configurable schedules. The platform additionally supports post-quantum cryptographic algorithms (lattice-based) to provide protection against future quantum computing threats. All key lifecycle events are recorded in the immutable audit trail.",
			Capabilities: []string{"encrypted-at-rest", "key-management", "pqc-cryptography", "audit-trail"},
		},
		{
			ID:       "SEC-ENC-002",
			Category: "Encryption",
			Question: "Does the platform encrypt data in transit? What protocols and cipher suites are supported?",
			Response: "All inter-node and client-server communication uses TLS 1.3 with post-quantum key exchange (hybrid classical + lattice-based). Legacy protocol versions (TLS 1.0, 1.1, 1.2) are disabled by default. The platform enforces minimum cipher suite requirements and logs all connection establishment events for audit purposes.",
			Capabilities: []string{"encrypted-transit", "pqc-cryptography", "audit-trail"},
		},
		{
			ID:       "SEC-ENC-003",
			Category: "Encryption",
			Question: "How are cryptographic keys managed? Is there support for HSM-backed key storage?",
			Response: "Cryptographic keys are managed through a dedicated key lifecycle management subsystem backed by Hardware Security Modules. The system supports automated key generation, rotation, revocation, and destruction. All key operations are logged in the hash-chained audit trail. Post-quantum cryptographic key pairs are supported for long-term data protection.",
			Capabilities: []string{"key-management", "pqc-cryptography", "audit-trail"},
		},

		// Access Control
		{
			ID:       "SEC-AC-001",
			Category: "Access Control",
			Question: "Describe the access control model. Does the platform support role-based access control (RBAC)?",
			Response: "The platform implements a comprehensive Role-Based Access Control system with on-chain governance for policy management. Access policies are enforced at the protocol level with support for fine-grained permission assignments. All access control changes require governance approval through a quorum-based proposal system, and every authorization decision is recorded in the immutable audit trail.",
			Capabilities: []string{"rbac-governance", "access-control", "audit-trail", "immutable-ledger"},
		},
		{
			ID:       "SEC-AC-002",
			Category: "Access Control",
			Question: "Does the platform support multi-factor authentication (MFA)?",
			Response: "The platform supports multi-factor authentication including hardware token support and cryptographic certificate-based authentication. Authentication events are logged and monitored continuously. The system enforces configurable session management policies including automatic timeout and re-authentication requirements.",
			Capabilities: []string{"access-control", "pqc-cryptography", "continuous-monitoring"},
		},
		{
			ID:       "SEC-AC-003",
			Category: "Access Control",
			Question: "How does the platform implement the principle of least privilege?",
			Response: "Least privilege is enforced through the RBAC governance module with granular permission assignments at the function level. Role definitions specify the minimum permissions required for each operational responsibility. Privilege escalation requires governance approval, and all access scope changes are recorded on the immutable ledger.",
			Capabilities: []string{"rbac-governance", "access-control", "audit-trail"},
		},

		// Audit and Logging
		{
			ID:       "SEC-AUD-001",
			Category: "Audit and Logging",
			Question: "Describe the audit logging capabilities. Are logs tamper-evident?",
			Response: "The platform implements a hash-chained, append-only audit logging system where each record includes a SHA-256 digest chained to the previous record for tamper detection. Audit records are immutably stored on the distributed ledger and emitted as structured events. The system captures all security-relevant actions including access events, configuration changes, governance decisions, and computation attestations. Log integrity can be verified at any time through chain validation.",
			Capabilities: []string{"audit-trail", "immutable-ledger"},
		},
		{
			ID:       "SEC-AUD-002",
			Category: "Audit and Logging",
			Question: "What is the audit log retention period? Can logs be exported for external analysis?",
			Response: "Audit logs stored on the blockchain are retained indefinitely as part of the immutable ledger state. Configurable retention policies are available for operational log streams. Logs can be exported in JSON format for integration with external SIEM and log analysis platforms. The hash-chain integrity is preserved in exports, allowing independent verification.",
			Capabilities: []string{"audit-trail", "data-retention", "immutable-ledger"},
		},

		// Incident Response
		{
			ID:       "SEC-IR-001",
			Category: "Incident Response",
			Question: "Does the organization have a formal incident response plan? How are security incidents detected and managed?",
			Response: "The platform includes automated incident detection through continuous monitoring of system health, security events, and anomalous behavior patterns. The incident response system classifies events by severity and routes them through configurable escalation paths. All incident detection, response, and resolution activities are recorded in the immutable audit trail with cryptographic timestamps. The economic slashing mechanism provides automated enforcement for validator misbehavior.",
			Capabilities: []string{"incident-response", "continuous-monitoring", "audit-trail", "slashing-enforcement"},
		},

		// Data Integrity
		{
			ID:       "SEC-INT-001",
			Category: "Data Integrity",
			Question: "How does the platform ensure data and computation integrity?",
			Response: "Data and computation integrity is ensured through multiple complementary mechanisms: (1) Digital Seals provide cryptographic, tamper-evident attestation of AI model integrity and inference provenance; (2) Trusted Execution Environment attestation ensures compute operations occur in hardware-isolated secure enclaves; (3) Proof of Useful Work consensus provides decentralized verification of AI computations across multiple validators; (4) The immutable blockchain ledger provides distributed state consensus preventing unauthorized modifications.",
			Capabilities: []string{"digital-seal", "tee-attestation", "pouw-consensus", "verifiable-compute", "immutable-ledger"},
		},
		{
			ID:       "SEC-INT-002",
			Category: "Data Integrity",
			Question: "How is model provenance tracked and verified?",
			Response: "Model provenance is tracked end-to-end from training data through deployment via the Digital Seal system. Each model version receives a cryptographic attestation recording its architecture, training methodology, evaluation results, and deployment context. These attestations are stored on the immutable ledger, creating a verifiable chain of custody. Any model modification or redeployment requires a new Digital Seal, ensuring complete traceability.",
			Capabilities: []string{"model-provenance", "digital-seal", "immutable-ledger", "audit-trail"},
		},

		// Business Continuity
		{
			ID:       "SEC-BC-001",
			Category: "Business Continuity",
			Question: "What disaster recovery and business continuity measures are in place?",
			Response: "The platform supports multi-region deployment with automated failover and point-in-time recovery capabilities. The distributed consensus architecture inherently provides fault tolerance — the system continues operating as long as a sufficient quorum of validators is available. Blockchain state is replicated across all validator nodes, providing built-in redundancy. Regular disaster recovery testing validates recovery time and recovery point objectives.",
			Capabilities: []string{"disaster-recovery", "pouw-consensus", "immutable-ledger"},
		},

		// Compliance
		{
			ID:       "SEC-COMP-001",
			Category: "Compliance",
			Question: "What regulatory compliance frameworks does the platform support?",
			Response: "The platform maintains control mappings to NIST AI RMF 1.0, EU AI Act (2024/1689), CMMC 2.0, HIPAA Security Rule, SOC 2 Type II, and PCI-DSS v4.0. The compliance control mapping library provides automated evidence collection for the majority of controls, gap assessment with remediation recommendations, and export in OSCAL format for machine-readable compliance reporting. Assessment reports include per-control coverage analysis with evidence inventory.",
			Capabilities: []string{"audit-trail", "digital-seal", "immutable-ledger", "continuous-monitoring"},
		},
		{
			ID:       "SEC-COMP-002",
			Category: "Compliance",
			Question: "How does the platform support AI-specific regulatory requirements?",
			Response: "The platform is purpose-built for regulated AI infrastructure and addresses AI-specific regulatory requirements through: model provenance tracking for transparency and accountability; bias monitoring for fairness assessment; explainability capabilities for human oversight; Digital Seal attestations for conformity assessment; hash-chained audit trails for record-keeping obligations; and verifiable compute through TEE attestation and consensus verification. These capabilities directly map to requirements in the NIST AI RMF and EU AI Act.",
			Capabilities: []string{"model-provenance", "bias-monitoring", "explainability", "digital-seal", "audit-trail", "tee-attestation", "human-oversight"},
		},

		// Third-Party Risk
		{
			ID:       "SEC-TPR-001",
			Category: "Third-Party Risk",
			Question: "How does the platform manage third-party and supply chain risks?",
			Response: "Supply chain integrity is managed through the Digital Seal system which provides cryptographic attestation for all model components including third-party dependencies. The model provenance system tracks the complete lineage of training data, model architectures, and deployed artifacts. Validator participation is governed by the on-chain staking and slashing mechanism which provides economic incentives for honest behavior and penalties for misbehavior.",
			Capabilities: []string{"third-party-risk", "digital-seal", "model-provenance", "slashing-enforcement"},
		},

		// Change Management
		{
			ID:       "SEC-CM-001",
			Category: "Change Management",
			Question: "How are infrastructure and configuration changes managed and approved?",
			Response: "All infrastructure and parameter changes are managed through the on-chain governance system which requires formal proposals, quorum-based voting, and approval before execution. Every governance proposal, vote, and execution is recorded on the immutable ledger. The system supports configurable quorum thresholds and multi-signature requirements for critical changes. Emergency change procedures with post-hoc approval are available for incident response scenarios.",
			Capabilities: []string{"change-management", "rbac-governance", "immutable-ledger", "audit-trail"},
		},
	}
}

// ---------------------------------------------------------------------------
// RFP response templates
// ---------------------------------------------------------------------------

// RFPSection represents a section of an RFP/RFI response.
type RFPSection struct {
	// Title is the section heading.
	Title string `json:"title"`

	// Content is the pre-built response text.
	Content string `json:"content"`

	// Capabilities lists the platform capabilities referenced.
	Capabilities []string `json:"capabilities"`
}

// RFPResponse is a collection of pre-built RFP/RFI response sections.
type RFPResponse struct {
	// Name identifies this response template.
	Name string `json:"name"`

	// Sections contains the response content.
	Sections []RFPSection `json:"sections"`
}

// StandardRFPResponse returns an RFP response template covering common
// evaluation criteria for regulated enterprise AI infrastructure.
func StandardRFPResponse() *RFPResponse {
	return &RFPResponse{
		Name: "Enterprise AI Infrastructure RFP Response",
		Sections: []RFPSection{
			{
				Title:        "Security Architecture",
				Content:      "Aethelred implements a defense-in-depth security architecture combining post-quantum cryptography, hardware-isolated trusted execution environments, and blockchain-based immutable audit trails. All data is encrypted at rest (AES-256-GCM) and in transit (TLS 1.3 with PQC key exchange). Cryptographic key management is backed by Hardware Security Modules with automated lifecycle management.",
				Capabilities: []string{"pqc-cryptography", "tee-attestation", "encrypted-at-rest", "encrypted-transit", "key-management"},
			},
			{
				Title:        "AI Model Governance",
				Content:      "The platform provides end-to-end AI model governance through Digital Seals (cryptographic attestations of model integrity), model provenance tracking, and on-chain governance for deployment decisions. Every model version is attested with a tamper-evident Digital Seal that records architecture, training methodology, evaluation results, and deployment context on the immutable ledger.",
				Capabilities: []string{"digital-seal", "model-provenance", "rbac-governance", "immutable-ledger"},
			},
			{
				Title:        "Verifiable Computation",
				Content:      "Aethelred ensures computation integrity through Trusted Execution Environment attestation and Proof of Useful Work consensus. TEE attestation provides hardware-level guarantees that compute operations occurred in isolated secure enclaves. The PoUW consensus mechanism provides decentralized verification across multiple independent validators with economic penalties for dishonest behavior.",
				Capabilities: []string{"tee-attestation", "pouw-consensus", "verifiable-compute", "slashing-enforcement"},
			},
			{
				Title:        "Regulatory Compliance",
				Content:      "The platform maintains comprehensive control mappings to NIST AI RMF 1.0, EU AI Act, CMMC 2.0, HIPAA, SOC 2 Type II, and PCI-DSS v4.0. Automated evidence collection covers the majority of framework controls. Assessment reports with per-control gap analysis and remediation recommendations can be exported in JSON, CSV, and OSCAL formats for integration with GRC platforms.",
				Capabilities: []string{"audit-trail", "continuous-monitoring", "digital-seal"},
			},
			{
				Title:        "Audit Trail and Forensics",
				Content:      "A hash-chained, append-only audit logging system records all security-relevant actions with deterministic SHA-256 hashing for tamper detection. Each audit record is chained to the previous record and immutably stored on the blockchain. The system supports forensic analysis with query capabilities by time range, category, severity, and actor.",
				Capabilities: []string{"audit-trail", "immutable-ledger"},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Vendor assessment templates
// ---------------------------------------------------------------------------

// VendorAssessmentField represents a single field in a vendor assessment form.
type VendorAssessmentField struct {
	// Field is the assessment form field name.
	Field string `json:"field"`

	// Value is the pre-filled response.
	Value string `json:"value"`
}

// VendorAssessment is a collection of pre-filled vendor assessment fields.
type VendorAssessment struct {
	// Name identifies this assessment template.
	Name string `json:"name"`

	// Description provides context for the template.
	Description string `json:"description"`

	// Fields contains the pre-filled assessment fields.
	Fields []VendorAssessmentField `json:"fields"`
}

// StandardVendorAssessment returns a vendor assessment template with
// pre-filled responses for common procurement evaluation criteria.
func StandardVendorAssessment() *VendorAssessment {
	return &VendorAssessment{
		Name:        "Standard Vendor Security Assessment",
		Description: "Pre-filled responses for common vendor assessment questionnaires used in enterprise procurement evaluation.",
		Fields: []VendorAssessmentField{
			{Field: "Data Encryption Standard", Value: "AES-256-GCM at rest; TLS 1.3 with post-quantum key exchange in transit"},
			{Field: "Key Management", Value: "HSM-backed key lifecycle management with automated rotation and revocation"},
			{Field: "Access Control Model", Value: "Role-Based Access Control with on-chain governance and least privilege enforcement"},
			{Field: "Authentication Methods", Value: "Multi-factor authentication with hardware token and cryptographic certificate support"},
			{Field: "Audit Logging", Value: "Hash-chained append-only audit trail with SHA-256 tamper detection, stored on immutable blockchain"},
			{Field: "Incident Response", Value: "Automated detection, classification, and response with on-chain evidence preservation"},
			{Field: "Data Integrity", Value: "Cryptographic Digital Seals, TEE attestation, and distributed consensus verification"},
			{Field: "Business Continuity", Value: "Multi-region deployment with distributed consensus providing inherent fault tolerance"},
			{Field: "Vulnerability Management", Value: "Continuous scanning with risk-prioritized remediation tracking"},
			{Field: "Change Management", Value: "On-chain governance proposals with quorum-based approval for all infrastructure changes"},
			{Field: "Compliance Frameworks", Value: "NIST AI RMF 1.0, EU AI Act, CMMC 2.0, HIPAA, SOC 2 Type II, PCI-DSS v4.0"},
			{Field: "Cryptographic Standards", Value: "Post-quantum cryptography (lattice-based) with HSM backing; quantum-resistant key exchange"},
			{Field: "Model Governance", Value: "End-to-end provenance tracking with Digital Seal attestations for every model version"},
			{Field: "AI Risk Management", Value: "Bias monitoring, explainability, human oversight workflows, and structured risk assessment"},
		},
	}
}
