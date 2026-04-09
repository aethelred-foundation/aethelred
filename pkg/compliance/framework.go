// Package compliance provides a productized compliance control mapping library
// that maps Aethelred platform capabilities to regulatory frameworks.
//
// Regulated enterprise buyers evaluate infrastructure platforms on control
// mappings, audit response readiness, and procurement artifacts. This package
// provides the foundational types and registry for framework definitions,
// control mappings, and coverage assessments.
//
// Supported frameworks include NIST AI RMF 1.0, EU AI Act, CMMC 2.0,
// HIPAA, SOC 2 Type II, and PCI-DSS v4.0.
package compliance

import (
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Coverage levels
// ---------------------------------------------------------------------------

// CoverageLevel indicates the degree to which an Aethelred capability
// satisfies a given regulatory control requirement.
type CoverageLevel int

const (
	// CoverageFull indicates the control is fully addressed by platform
	// capabilities with automated evidence collection.
	CoverageFull CoverageLevel = iota

	// CoveragePartial indicates the control is partially addressed;
	// additional configuration or organizational processes may be needed.
	CoveragePartial

	// CoveragePlanned indicates the capability is on the product roadmap
	// but not yet generally available.
	CoveragePlanned

	// CoverageNotApplicable indicates the control does not apply to the
	// platform's operational context.
	CoverageNotApplicable

	// CoverageGap indicates a gap where the control is not currently
	// addressed and requires remediation planning.
	CoverageGap
)

// String returns the human-readable label for a CoverageLevel.
func (c CoverageLevel) String() string {
	switch c {
	case CoverageFull:
		return "Full"
	case CoveragePartial:
		return "Partial"
	case CoveragePlanned:
		return "Planned"
	case CoverageNotApplicable:
		return "Not Applicable"
	case CoverageGap:
		return "Gap"
	default:
		return "Unknown"
	}
}

// Score returns a numeric score (0-100) for aggregation.
func (c CoverageLevel) Score() int {
	switch c {
	case CoverageFull:
		return 100
	case CoveragePartial:
		return 50
	case CoveragePlanned:
		return 25
	case CoverageNotApplicable:
		return 100 // Does not penalize the score
	case CoverageGap:
		return 0
	default:
		return 0
	}
}

// ParseCoverageLevel converts a string to a CoverageLevel.
func ParseCoverageLevel(s string) (CoverageLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "full":
		return CoverageFull, nil
	case "partial":
		return CoveragePartial, nil
	case "planned":
		return CoveragePlanned, nil
	case "not applicable", "not_applicable", "n/a":
		return CoverageNotApplicable, nil
	case "gap":
		return CoverageGap, nil
	default:
		return CoverageGap, fmt.Errorf("ParseCoverageLevel: %w: %s", ErrInvalidCoverageLevel, s)
	}
}

// ---------------------------------------------------------------------------
// Evidence requirements
// ---------------------------------------------------------------------------

// EvidenceType classifies the kind of evidence required for a control.
type EvidenceType string

const (
	EvidenceTypeLog           EvidenceType = "audit_log"
	EvidenceTypeAttestation   EvidenceType = "attestation"
	EvidenceTypeConfiguration EvidenceType = "configuration"
	EvidenceTypeReport        EvidenceType = "report"
	EvidenceTypeCertificate   EvidenceType = "certificate"
	EvidenceTypePolicy        EvidenceType = "policy_document"
	EvidenceTypeScreenshot    EvidenceType = "screenshot"
	EvidenceTypeTestResult    EvidenceType = "test_result"
)

// EvidenceRequirement describes a piece of evidence needed to demonstrate
// compliance with a control.
type EvidenceRequirement struct {
	// Type classifies the evidence (log, attestation, configuration, etc.).
	Type EvidenceType `json:"type"`

	// Description explains what the evidence must demonstrate.
	Description string `json:"description"`

	// Source identifies the system or process that produces the evidence.
	Source string `json:"source"`

	// Automated indicates whether the evidence can be collected without
	// manual intervention via platform APIs.
	Automated bool `json:"automated"`
}

// ---------------------------------------------------------------------------
// Control definition
// ---------------------------------------------------------------------------

// Control represents a single regulatory control within a framework.
type Control struct {
	// ID is the control identifier (e.g., "GOV-1", "Article 9").
	ID string `json:"id"`

	// Name is the short name or title of the control.
	Name string `json:"name"`

	// Description provides a detailed explanation of the control requirement.
	Description string `json:"description"`

	// Category groups controls within the framework (e.g., "Govern", "Map").
	Category string `json:"category"`

	// EvidenceRequirements lists the evidence needed to demonstrate compliance.
	EvidenceRequirements []EvidenceRequirement `json:"evidence_requirements"`

	// AethelredCapabilities lists the platform capabilities that address
	// this control.
	AethelredCapabilities []string `json:"aethelred_capabilities"`
}

// Validate performs basic validation on a Control definition.
func (c *Control) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("Control.Validate: %w: control ID is required", ErrInvalidInput)
	}
	if c.Name == "" {
		return fmt.Errorf("Control.Validate: %w: control %s: name is required", ErrInvalidInput, c.ID)
	}
	if c.Description == "" {
		return fmt.Errorf("Control.Validate: %w: control %s: description is required", ErrInvalidInput, c.ID)
	}
	if c.Category == "" {
		return fmt.Errorf("Control.Validate: %w: control %s: category is required", ErrInvalidInput, c.ID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Framework definition
// ---------------------------------------------------------------------------

// FrameworkCategory classifies the regulatory domain of a framework.
type FrameworkCategory string

const (
	FrameworkCategoryAI         FrameworkCategory = "AI Governance"
	FrameworkCategoryGovernment FrameworkCategory = "Government"
	FrameworkCategoryHealthcare FrameworkCategory = "Healthcare"
	FrameworkCategoryFinancial  FrameworkCategory = "Financial"
	FrameworkCategorySecurity   FrameworkCategory = "Security"
	FrameworkCategoryPrivacy    FrameworkCategory = "Privacy"
	FrameworkCategoryCrossSector FrameworkCategory = "Cross-Sector"
)

// Framework represents a complete regulatory compliance framework with its
// controls and metadata.
type Framework struct {
	// ID is the unique identifier for the framework (e.g., "nist-ai-rmf").
	ID string `json:"id"`

	// Name is the full display name of the framework.
	Name string `json:"name"`

	// Version identifies the specific version of the framework.
	Version string `json:"version"`

	// Description provides a summary of the framework's purpose and scope.
	Description string `json:"description"`

	// Category classifies the regulatory domain.
	Category FrameworkCategory `json:"category"`

	// Authority identifies the issuing organization.
	Authority string `json:"authority"`

	// EffectiveDate is when this version of the framework became effective.
	EffectiveDate time.Time `json:"effective_date"`

	// Controls contains all controls defined by the framework.
	Controls []Control `json:"controls"`
}

// Validate performs structural validation on a Framework definition.
func (f *Framework) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("Framework.Validate: %w: framework ID is required", ErrInvalidInput)
	}
	if f.Name == "" {
		return fmt.Errorf("Framework.Validate: %w: framework %s: name is required", ErrInvalidInput, f.ID)
	}
	if f.Version == "" {
		return fmt.Errorf("Framework.Validate: %w: framework %s: version is required", ErrInvalidInput, f.ID)
	}
	if len(f.Controls) == 0 {
		return fmt.Errorf("Framework.Validate: %w: framework %s: at least one control is required", ErrInvalidInput, f.ID)
	}

	seen := make(map[string]bool)
	for i := range f.Controls {
		if err := f.Controls[i].Validate(); err != nil {
			return fmt.Errorf("framework %s: %w", f.ID, err)
		}
		if seen[f.Controls[i].ID] {
			return fmt.Errorf("framework %s: duplicate control ID %s", f.ID, f.Controls[i].ID)
		}
		seen[f.Controls[i].ID] = true
	}
	return nil
}

// GetControl returns the control with the given ID, or nil if not found.
func (f *Framework) GetControl(controlID string) *Control {
	for i := range f.Controls {
		if f.Controls[i].ID == controlID {
			return &f.Controls[i]
		}
	}
	return nil
}

// GetControlsByCategory returns all controls matching the given category.
func (f *Framework) GetControlsByCategory(category string) []Control {
	var result []Control
	for _, c := range f.Controls {
		if c.Category == category {
			result = append(result, c)
		}
	}
	return result
}

// Categories returns the distinct control categories in this framework.
func (f *Framework) Categories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, c := range f.Controls {
		if !seen[c.Category] {
			seen[c.Category] = true
			cats = append(cats, c.Category)
		}
	}
	return cats
}

// ---------------------------------------------------------------------------
// Control mapping
// ---------------------------------------------------------------------------

// ControlMapping describes how a specific framework control maps to an
// Aethelred platform capability with coverage assessment.
type ControlMapping struct {
	// FrameworkID identifies the parent framework.
	FrameworkID string `json:"framework_id"`

	// ControlID identifies the specific control within the framework.
	ControlID string `json:"control_id"`

	// AethelredCapability identifies the platform capability providing
	// coverage (e.g., "digital-seal", "tee-attestation").
	AethelredCapability string `json:"aethelred_capability"`

	// CoverageLevel indicates the degree of coverage.
	CoverageLevel CoverageLevel `json:"coverage_level"`

	// Evidence describes the evidence that can be produced to demonstrate
	// this mapping.
	Evidence string `json:"evidence"`

	// GapDescription describes any remaining gap if coverage is not full.
	GapDescription string `json:"gap_description,omitempty"`

	// RemediationSteps describes recommended actions to close a gap.
	RemediationSteps string `json:"remediation_steps,omitempty"`

	// ImplementationNotes provides additional context for the mapping.
	ImplementationNotes string `json:"implementation_notes,omitempty"`
}

// Validate performs basic validation on a ControlMapping.
func (m *ControlMapping) Validate() error {
	if m.FrameworkID == "" {
		return fmt.Errorf("ControlMapping.Validate: %w: framework ID is required", ErrInvalidInput)
	}
	if m.ControlID == "" {
		return fmt.Errorf("ControlMapping.Validate: %w: control ID is required", ErrInvalidInput)
	}
	if m.AethelredCapability == "" && m.CoverageLevel != CoverageGap && m.CoverageLevel != CoverageNotApplicable {
		return fmt.Errorf("ControlMapping.Validate: %w: aethelred capability is required for non-gap mappings", ErrInvalidInput)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Aethelred capability constants
// ---------------------------------------------------------------------------
// These constants identify the platform capabilities referenced across
// all framework control mappings.

const (
	CapDigitalSeal          = "digital-seal"
	CapTEEAttestation       = "tee-attestation"
	CapPoUWConsensus        = "pouw-consensus"
	CapAuditTrail           = "audit-trail"
	CapPQCCrypto            = "pqc-cryptography"
	CapModelProvenance      = "model-provenance"
	CapImmutableLedger      = "immutable-ledger"
	CapRBACGovernance       = "rbac-governance"
	CapVerifiableCompute    = "verifiable-compute"
	CapSlashingEnforcement  = "slashing-enforcement"
	CapEncryptedTransit     = "encrypted-transit"
	CapEncryptedAtRest      = "encrypted-at-rest"
	CapKeyManagement        = "key-management"
	CapIncidentResponse     = "incident-response"
	CapContinuousMonitoring = "continuous-monitoring"
	CapDataClassification   = "data-classification"
	CapAccessControl        = "access-control"
	CapChangeManagement     = "change-management"
	CapDisasterRecovery     = "disaster-recovery"
	CapVulnerabilityMgmt    = "vulnerability-management"
	CapPenetrationTesting   = "penetration-testing"
	CapSecurityTraining     = "security-training"
	CapThirdPartyRisk       = "third-party-risk"
	CapPrivacyControls      = "privacy-controls"
	CapDataRetention        = "data-retention"
	CapConsentManagement    = "consent-management"
	CapBiasMonitoring       = "bias-monitoring"
	CapExplainability       = "explainability"
	CapHumanOversight       = "human-oversight"
	CapRiskAssessment       = "risk-assessment"
)

// CapabilityDescription returns a human-readable description for a
// platform capability constant.
func CapabilityDescription(cap string) string {
	descriptions := map[string]string{
		CapDigitalSeal:          "Cryptographic Digital Seals providing tamper-evident, non-repudiable attestation of AI model integrity and inference provenance",
		CapTEEAttestation:       "Trusted Execution Environment attestation ensuring compute operations occur in hardware-isolated secure enclaves",
		CapPoUWConsensus:        "Proof of Useful Work consensus mechanism providing decentralized verification of AI computation",
		CapAuditTrail:           "Hash-chained, append-only audit logging with deterministic record hashing for tamper detection",
		CapPQCCrypto:            "Post-Quantum Cryptography using lattice-based algorithms resistant to quantum computing attacks",
		CapModelProvenance:      "End-to-end model lifecycle tracking from training data through deployment with cryptographic attestation",
		CapImmutableLedger:      "Cosmos SDK-based blockchain ledger providing immutable, distributed state consensus",
		CapRBACGovernance:       "Role-Based Access Control with on-chain governance for policy management and authority delegation",
		CapVerifiableCompute:    "Cryptographic verification that computation was performed correctly using zero-knowledge proofs and TEE attestation",
		CapSlashingEnforcement:  "Economic penalty mechanism for validator misbehavior with graduated severity levels",
		CapEncryptedTransit:     "TLS 1.3 with post-quantum key exchange for all inter-node and client-server communication",
		CapEncryptedAtRest:      "AES-256-GCM encryption for all persistent storage with hardware security module key management",
		CapKeyManagement:        "Hardware Security Module-backed key lifecycle management with automated rotation and revocation",
		CapIncidentResponse:     "Automated incident detection, classification, and response with on-chain evidence preservation",
		CapContinuousMonitoring: "Real-time system health, security event, and compliance posture monitoring with alerting",
		CapDataClassification:   "Automated data classification and labeling with policy-driven handling requirements",
		CapAccessControl:        "Multi-factor authentication with hardware token support and granular permission management",
		CapChangeManagement:     "On-chain governance proposals for infrastructure changes with quorum-based approval",
		CapDisasterRecovery:     "Multi-region deployment with automated failover and point-in-time recovery capabilities",
		CapVulnerabilityMgmt:    "Continuous vulnerability scanning with automated patching and risk-prioritized remediation",
		CapPenetrationTesting:   "Regular third-party penetration testing with findings tracked through remediation",
		CapSecurityTraining:     "Role-based security awareness training program with completion tracking",
		CapThirdPartyRisk:       "Vendor assessment and continuous monitoring program for supply chain dependencies",
		CapPrivacyControls:      "Privacy-by-design controls including data minimization, purpose limitation, and anonymization",
		CapDataRetention:        "Configurable data retention policies with automated enforcement and secure deletion",
		CapConsentManagement:    "Granular consent collection, storage, and withdrawal processing capabilities",
		CapBiasMonitoring:       "Continuous monitoring of model outputs for demographic bias and fairness metrics",
		CapExplainability:       "Model decision explanation capabilities with feature attribution and counterfactual analysis",
		CapHumanOversight:       "Human-in-the-loop review workflows with escalation paths and override capabilities",
		CapRiskAssessment:       "Structured risk assessment framework with quantitative scoring and mitigation tracking",
	}

	if desc, ok := descriptions[cap]; ok {
		return desc
	}
	return "Platform capability"
}
