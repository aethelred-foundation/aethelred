// Package defense provides integration types and controllers for defense
// deployment scenarios including CMMC 2.0 compliance assessment, air-gapped
// operations, KMS/HSM key management, procurement artifact generation, and
// data classification enforcement.
package defense

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// CMMC 2.0 Level 2/3 Controls
// ---------------------------------------------------------------------------

// CMMCLevel represents a CMMC 2.0 maturity level.
type CMMCLevel int

const (
	CMMCLevel1 CMMCLevel = iota + 1
	CMMCLevel2
	CMMCLevel3
)

// String returns the human-readable label for a CMMC level.
func (l CMMCLevel) String() string {
	switch l {
	case CMMCLevel1:
		return "Level 1 (Foundational)"
	case CMMCLevel2:
		return "Level 2 (Advanced)"
	case CMMCLevel3:
		return "Level 3 (Expert)"
	default:
		return "Unknown"
	}
}

// CMMCDomain represents one of the 14 CMMC 2.0 security domains.
type CMMCDomain struct {
	// ID is the short identifier (e.g. "AC", "AU").
	ID string `json:"id"`

	// Name is the full domain name.
	Name string `json:"name"`

	// Description explains the domain scope.
	Description string `json:"description"`

	// Practices lists the practices within this domain.
	Practices []CMMCPractice `json:"practices"`
}

// CMMCPractice represents a single CMMC practice requirement.
type CMMCPractice struct {
	// ID is the practice identifier (e.g. "AC.L2-3.1.1").
	ID string `json:"id"`

	// Description explains what this practice requires.
	Description string `json:"description"`

	// Level is the minimum CMMC level at which this practice is required.
	Level CMMCLevel `json:"level"`

	// Domain is the parent domain identifier.
	Domain string `json:"domain"`

	// AethelredMapping describes how the Aethelred platform addresses this practice.
	AethelredMapping string `json:"aethelred_mapping"`

	// Evidence lists the evidence types that demonstrate compliance.
	Evidence []string `json:"evidence"`

	// NISTReference maps to the NIST SP 800-171 control.
	NISTReference string `json:"nist_reference"`
}

// CMMCAssessment contains the results of a CMMC compliance assessment.
type CMMCAssessment struct {
	// ID uniquely identifies this assessment.
	ID string `json:"id"`

	// TargetLevel is the CMMC level being assessed against.
	TargetLevel CMMCLevel `json:"target_level"`

	// Timestamp records when the assessment was performed.
	Timestamp time.Time `json:"timestamp"`

	// TotalPractices is the count of practices at the target level.
	TotalPractices int `json:"total_practices"`

	// SatisfiedPractices counts practices that are met.
	SatisfiedPractices int `json:"satisfied_practices"`

	// PartialPractices counts practices that are partially met.
	PartialPractices int `json:"partial_practices"`

	// GapPractices counts practices that are not met.
	GapPractices int `json:"gap_practices"`

	// DomainResults contains per-domain assessment detail.
	DomainResults []DomainAssessment `json:"domain_results"`

	// OverallScore is a percentage (0-100).
	OverallScore float64 `json:"overall_score"`

	// Compliant indicates whether the target level is fully met.
	Compliant bool `json:"compliant"`

	// Gaps lists practice IDs that have gaps.
	Gaps []string `json:"gaps"`

	// Recommendations lists remediation guidance for each gap.
	Recommendations []string `json:"recommendations"`
}

// DomainAssessment holds the assessment results for a single domain.
type DomainAssessment struct {
	DomainID   string  `json:"domain_id"`
	DomainName string  `json:"domain_name"`
	Total      int     `json:"total"`
	Satisfied  int     `json:"satisfied"`
	Partial    int     `json:"partial"`
	Gaps       int     `json:"gaps"`
	Score      float64 `json:"score"`
}

// CMMCAssessor evaluates compliance against CMMC 2.0 domains and practices.
type CMMCAssessor struct {
	domains []CMMCDomain
}

// NewCMMCAssessor creates a new assessor pre-loaded with the 14 CMMC domains.
func NewCMMCAssessor() *CMMCAssessor {
	return &CMMCAssessor{
		domains: buildCMMCDomains(),
	}
}

// AssessCMMC evaluates the platform against the specified CMMC level and
// returns a comprehensive assessment.
func (a *CMMCAssessor) AssessCMMC(_ context.Context, level CMMCLevel) (*CMMCAssessment, error) {
	if level < CMMCLevel1 || level > CMMCLevel3 {
		return nil, fmt.Errorf("invalid CMMC level: %d", level)
	}

	required := a.GetRequiredPractices(level)

	assessment := &CMMCAssessment{
		ID:          fmt.Sprintf("cmmc-assessment-%d", time.Now().UnixNano()),
		TargetLevel: level,
		Timestamp:   time.Now().UTC(),
	}

	domainMap := make(map[string]*DomainAssessment)
	for _, d := range a.domains {
		domainMap[d.ID] = &DomainAssessment{
			DomainID:   d.ID,
			DomainName: d.Name,
		}
	}

	for _, p := range required {
		assessment.TotalPractices++
		da := domainMap[p.Domain]
		if da == nil {
			continue
		}
		da.Total++

		if p.AethelredMapping != "" && !strings.HasPrefix(p.AethelredMapping, "gap:") {
			if strings.HasPrefix(p.AethelredMapping, "partial:") {
				assessment.PartialPractices++
				da.Partial++
			} else {
				assessment.SatisfiedPractices++
				da.Satisfied++
			}
		} else {
			assessment.GapPractices++
			da.Gaps++
			assessment.Gaps = append(assessment.Gaps, p.ID)
			assessment.Recommendations = append(assessment.Recommendations,
				fmt.Sprintf("[%s] %s — requires remediation", p.ID, p.Description))
		}
	}

	for _, da := range domainMap {
		if da.Total > 0 {
			da.Score = float64(da.Satisfied*100+da.Partial*50) / float64(da.Total)
		}
		assessment.DomainResults = append(assessment.DomainResults, *da)
	}

	if assessment.TotalPractices > 0 {
		assessment.OverallScore = float64(assessment.SatisfiedPractices*100+assessment.PartialPractices*50) / float64(assessment.TotalPractices)
	}
	assessment.Compliant = assessment.GapPractices == 0

	return assessment, nil
}

// GetRequiredPractices returns all practices required at the specified CMMC level.
func (a *CMMCAssessor) GetRequiredPractices(level CMMCLevel) []CMMCPractice {
	var practices []CMMCPractice
	for _, d := range a.domains {
		for _, p := range d.Practices {
			if p.Level <= level {
				practices = append(practices, p)
			}
		}
	}
	return practices
}

// GetDomains returns all 14 CMMC domains.
func (a *CMMCAssessor) GetDomains() []CMMCDomain {
	return a.domains
}

// ---------------------------------------------------------------------------
// Domain definitions — 14 CMMC 2.0 domains with representative practices
// ---------------------------------------------------------------------------

func buildCMMCDomains() []CMMCDomain {
	return []CMMCDomain{
		{
			ID: "AC", Name: "Access Control",
			Description: "Limit system access to authorized users and transactions.",
			Practices: []CMMCPractice{
				{ID: "AC.L2-3.1.1", Description: "Limit system access to authorized users, processes acting on behalf of authorized users, and devices.", Level: CMMCLevel2, Domain: "AC", AethelredMapping: "Role-based access control via seal-level permissions and TEE-validated identity", Evidence: []string{"access_policy", "seal_audit_trail"}, NISTReference: "3.1.1"},
				{ID: "AC.L2-3.1.2", Description: "Limit system access to the types of transactions and functions that authorized users are permitted to execute.", Level: CMMCLevel2, Domain: "AC", AethelredMapping: "Transaction-level authorization enforced by blockchain consensus", Evidence: []string{"transaction_logs", "policy_config"}, NISTReference: "3.1.2"},
				{ID: "AC.L2-3.1.3", Description: "Control the flow of CUI in accordance with approved authorizations.", Level: CMMCLevel2, Domain: "AC", AethelredMapping: "Data classification enforcement with seal-backed flow controls", Evidence: []string{"classification_policy", "flow_audit"}, NISTReference: "3.1.3"},
			},
		},
		{
			ID: "AU", Name: "Audit & Accountability",
			Description: "Create, protect, and retain audit records.",
			Practices: []CMMCPractice{
				{ID: "AU.L2-3.3.1", Description: "Create and retain system audit logs and records.", Level: CMMCLevel2, Domain: "AU", AethelredMapping: "Immutable blockchain-anchored audit trail with hash-chained records", Evidence: []string{"audit_chain", "retention_policy"}, NISTReference: "3.3.1"},
				{ID: "AU.L2-3.3.2", Description: "Ensure actions of individual system users can be uniquely traced.", Level: CMMCLevel2, Domain: "AU", AethelredMapping: "Seal requester identity linked to bech32 address with TEE attestation", Evidence: []string{"seal_records", "identity_mapping"}, NISTReference: "3.3.2"},
			},
		},
		{
			ID: "AT", Name: "Awareness & Training",
			Description: "Ensure personnel are aware of security risks.",
			Practices: []CMMCPractice{
				{ID: "AT.L2-3.2.1", Description: "Ensure managers, systems administrators, and users are made aware of the security risks.", Level: CMMCLevel2, Domain: "AT", AethelredMapping: "partial: Platform provides security documentation; org-level training required", Evidence: []string{"documentation", "training_records"}, NISTReference: "3.2.1"},
				{ID: "AT.L2-3.2.2", Description: "Ensure personnel are trained to carry out their assigned information security-related duties.", Level: CMMCLevel2, Domain: "AT", AethelredMapping: "partial: SDK documentation and operational guides provided", Evidence: []string{"sdk_docs", "runbooks"}, NISTReference: "3.2.2"},
			},
		},
		{
			ID: "CM", Name: "Configuration Management",
			Description: "Establish and maintain baseline configurations.",
			Practices: []CMMCPractice{
				{ID: "CM.L2-3.4.1", Description: "Establish and maintain baseline configurations and inventories of organizational systems.", Level: CMMCLevel2, Domain: "CM", AethelredMapping: "Infrastructure-as-code with Terraform/Helm baselines and sealed deployment manifests", Evidence: []string{"terraform_state", "helm_values", "deployment_seals"}, NISTReference: "3.4.1"},
				{ID: "CM.L2-3.4.2", Description: "Establish and enforce security configuration settings.", Level: CMMCLevel2, Domain: "CM", AethelredMapping: "Hardened container images with TEE measurement verification", Evidence: []string{"container_scan", "tee_measurement"}, NISTReference: "3.4.2"},
			},
		},
		{
			ID: "IA", Name: "Identification & Authentication",
			Description: "Identify and authenticate users and devices.",
			Practices: []CMMCPractice{
				{ID: "IA.L2-3.5.1", Description: "Identify system users, processes, and devices.", Level: CMMCLevel2, Domain: "IA", AethelredMapping: "Cryptographic identity via bech32 addresses backed by PQ-safe key pairs", Evidence: []string{"key_registry", "identity_proofs"}, NISTReference: "3.5.1"},
				{ID: "IA.L2-3.5.2", Description: "Authenticate identities before allowing access to systems.", Level: CMMCLevel2, Domain: "IA", AethelredMapping: "ML-DSA-65 digital signatures with HSM-backed key storage", Evidence: []string{"auth_logs", "hsm_audit"}, NISTReference: "3.5.2"},
			},
		},
		{
			ID: "IR", Name: "Incident Response",
			Description: "Establish operational incident-handling capability.",
			Practices: []CMMCPractice{
				{ID: "IR.L2-3.6.1", Description: "Establish an operational incident-handling capability.", Level: CMMCLevel2, Domain: "IR", AethelredMapping: "Sealed incident records with immutable timelines and evidence bundles", Evidence: []string{"incident_records", "evidence_bundles"}, NISTReference: "3.6.1"},
				{ID: "IR.L2-3.6.2", Description: "Track, document, and report incidents.", Level: CMMCLevel2, Domain: "IR", AethelredMapping: "Blockchain-anchored incident tracking with automated compliance reporting", Evidence: []string{"incident_timeline", "compliance_reports"}, NISTReference: "3.6.2"},
			},
		},
		{
			ID: "MA", Name: "Maintenance",
			Description: "Perform maintenance on organizational systems.",
			Practices: []CMMCPractice{
				{ID: "MA.L2-3.7.1", Description: "Perform maintenance on organizational systems.", Level: CMMCLevel2, Domain: "MA", AethelredMapping: "partial: Maintenance windows tracked via sealed state transitions", Evidence: []string{"maintenance_logs"}, NISTReference: "3.7.1"},
			},
		},
		{
			ID: "MP", Name: "Media Protection",
			Description: "Protect system media containing CUI.",
			Practices: []CMMCPractice{
				{ID: "MP.L2-3.8.1", Description: "Protect system media containing CUI, both paper and digital.", Level: CMMCLevel2, Domain: "MP", AethelredMapping: "Encrypted storage with classification-based access controls", Evidence: []string{"encryption_config", "access_logs"}, NISTReference: "3.8.1"},
			},
		},
		{
			ID: "PS", Name: "Personnel Security",
			Description: "Screen individuals prior to authorizing access.",
			Practices: []CMMCPractice{
				{ID: "PS.L2-3.9.1", Description: "Screen individuals prior to authorizing access to systems containing CUI.", Level: CMMCLevel2, Domain: "PS", AethelredMapping: "gap: Personnel screening is an organizational responsibility", Evidence: []string{"screening_records"}, NISTReference: "3.9.1"},
			},
		},
		{
			ID: "PE", Name: "Physical Protection",
			Description: "Limit physical access to organizational systems.",
			Practices: []CMMCPractice{
				{ID: "PE.L2-3.10.1", Description: "Limit physical access to organizational systems, equipment, and operating environments.", Level: CMMCLevel2, Domain: "PE", AethelredMapping: "gap: Physical access control is an organizational/facility responsibility", Evidence: []string{"physical_access_logs"}, NISTReference: "3.10.1"},
			},
		},
		{
			ID: "RA", Name: "Risk Assessment",
			Description: "Assess risk to organizational operations.",
			Practices: []CMMCPractice{
				{ID: "RA.L2-3.11.1", Description: "Periodically assess the risk to organizational operations.", Level: CMMCLevel2, Domain: "RA", AethelredMapping: "Automated compliance assessment with sealed evidence packages", Evidence: []string{"risk_assessment", "compliance_report"}, NISTReference: "3.11.1"},
				{ID: "RA.L2-3.11.2", Description: "Scan for vulnerabilities in organizational systems periodically.", Level: CMMCLevel2, Domain: "RA", AethelredMapping: "Container image scanning with sealed vulnerability reports", Evidence: []string{"vuln_scan", "scan_seals"}, NISTReference: "3.11.2"},
			},
		},
		{
			ID: "CA", Name: "Security Assessment",
			Description: "Assess security controls for effectiveness.",
			Practices: []CMMCPractice{
				{ID: "CA.L2-3.12.1", Description: "Periodically assess the security controls in organizational systems.", Level: CMMCLevel2, Domain: "CA", AethelredMapping: "Continuous compliance monitoring with seal-backed assessment evidence", Evidence: []string{"assessment_records", "compliance_dashboard"}, NISTReference: "3.12.1"},
			},
		},
		{
			ID: "SC", Name: "System & Communications Protection",
			Description: "Monitor, control, and protect communications.",
			Practices: []CMMCPractice{
				{ID: "SC.L2-3.13.1", Description: "Monitor, control, and protect communications at external and key internal boundaries.", Level: CMMCLevel2, Domain: "SC", AethelredMapping: "TLS 1.3 with ML-DSA-65 certificates for all inter-node communication", Evidence: []string{"tls_config", "cert_inventory"}, NISTReference: "3.13.1"},
				{ID: "SC.L2-3.13.2", Description: "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security.", Level: CMMCLevel2, Domain: "SC", AethelredMapping: "Defense-in-depth architecture with TEE enclaves and air-gap support", Evidence: []string{"architecture_docs", "tee_config"}, NISTReference: "3.13.2"},
			},
		},
		{
			ID: "SI", Name: "System & Information Integrity",
			Description: "Identify, report, and correct system flaws in a timely manner.",
			Practices: []CMMCPractice{
				{ID: "SI.L2-3.14.1", Description: "Identify, report, and correct system flaws in a timely manner.", Level: CMMCLevel2, Domain: "SI", AethelredMapping: "Sealed patch management records with evidence of timely remediation", Evidence: []string{"patch_records", "remediation_seals"}, NISTReference: "3.14.1"},
				{ID: "SI.L2-3.14.2", Description: "Provide protection from malicious code at designated locations.", Level: CMMCLevel2, Domain: "SI", AethelredMapping: "TEE-isolated execution prevents code tampering; integrity verified by consensus", Evidence: []string{"tee_attestation", "consensus_proof"}, NISTReference: "3.14.2"},
			},
		},
	}
}
