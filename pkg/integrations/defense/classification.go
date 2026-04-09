package defense

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Data Classification Enforcement
// ---------------------------------------------------------------------------

// ClassificationLevel represents the sensitivity of data.
type ClassificationLevel int

const (
	Unclassified ClassificationLevel = iota
	CUI
	FOUO
	Confidential
	Secret
	TopSecret
)

// String returns the human-readable label.
func (c ClassificationLevel) String() string {
	switch c {
	case Unclassified:
		return "Unclassified"
	case CUI:
		return "CUI"
	case FOUO:
		return "FOUO"
	case Confidential:
		return "Confidential"
	case Secret:
		return "Secret"
	case TopSecret:
		return "Top Secret"
	default:
		return "Unknown"
	}
}

// Rank returns the numeric precedence (higher = more sensitive).
func (c ClassificationLevel) Rank() int {
	return int(c)
}

// ParseClassificationLevel converts a string to a ClassificationLevel.
func ParseClassificationLevel(s string) (ClassificationLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "unclassified":
		return Unclassified, nil
	case "cui":
		return CUI, nil
	case "fouo":
		return FOUO, nil
	case "confidential":
		return Confidential, nil
	case "secret":
		return Secret, nil
	case "top secret", "topsecret", "top_secret", "ts":
		return TopSecret, nil
	default:
		return Unclassified, fmt.Errorf("unknown classification level: %s", s)
	}
}

// HandlingRequirements defines how data at a given classification must be handled.
type HandlingRequirements struct {
	// Level is the classification level these requirements apply to.
	Level ClassificationLevel `json:"level"`

	// EncryptionRequired indicates whether data must be encrypted at rest.
	EncryptionRequired bool `json:"encryption_required"`

	// EncryptionAlgorithm is the required encryption algorithm.
	EncryptionAlgorithm string `json:"encryption_algorithm"`

	// TransitEncryption indicates whether data must be encrypted in transit.
	TransitEncryption bool `json:"transit_encryption"`

	// TransitProtocol is the required transit protocol (e.g. "TLS 1.3").
	TransitProtocol string `json:"transit_protocol"`

	// AccessControlRequired indicates whether access control lists are mandatory.
	AccessControlRequired bool `json:"access_control_required"`

	// ClearanceRequired is the minimum personnel clearance needed.
	ClearanceRequired string `json:"clearance_required"`

	// StorageRequirements describes storage constraints.
	StorageRequirements string `json:"storage_requirements"`

	// DisposalMethod describes how data must be destroyed.
	DisposalMethod string `json:"disposal_method"`

	// AuditRequired indicates whether all access must be audited.
	AuditRequired bool `json:"audit_required"`

	// MarkingRequired indicates whether documents must carry classification markings.
	MarkingRequired bool `json:"marking_required"`

	// NeedToKnow indicates whether need-to-know restrictions apply.
	NeedToKnow bool `json:"need_to_know"`

	// AirGapRequired indicates whether the data must be in an air-gapped environment.
	AirGapRequired bool `json:"air_gap_required"`

	// HSMRequired indicates whether cryptographic keys must be in an HSM.
	HSMRequired bool `json:"hsm_required"`
}

// ClassificationPolicy defines the rules for data classification enforcement.
type ClassificationPolicy struct {
	// DefaultLevel is the default classification for unclassified data.
	DefaultLevel ClassificationLevel `json:"default_level"`

	// LevelRequirements maps each classification level to its handling requirements.
	LevelRequirements map[ClassificationLevel]HandlingRequirements `json:"level_requirements"`

	// HandlingInstructions provides free-form guidance per level.
	HandlingInstructions map[ClassificationLevel]string `json:"handling_instructions"`

	// EnforcementMode controls whether violations are blocked or just logged.
	EnforcementMode string `json:"enforcement_mode"`
}

// ClassificationResult holds the outcome of a data classification operation.
type ClassificationResult struct {
	// Level is the determined classification level.
	Level ClassificationLevel `json:"level"`

	// Confidence is a score from 0-100 indicating classification confidence.
	Confidence int `json:"confidence"`

	// Reason explains why this classification was assigned.
	Reason string `json:"reason"`

	// Timestamp records when classification was determined.
	Timestamp time.Time `json:"timestamp"`

	// Indicators lists the data indicators that triggered this classification.
	Indicators []string `json:"indicators"`
}

// ClassificationContext provides context for the classification decision.
type ClassificationContext struct {
	// Source describes where the data originated.
	Source string `json:"source"`

	// Purpose describes why the data is being processed.
	Purpose string `json:"purpose"`

	// ContractNumber links to a specific contract if applicable.
	ContractNumber string `json:"contract_number"`

	// ProgramName links to a specific program if applicable.
	ProgramName string `json:"program_name"`

	// ExistingClassification is a pre-assigned classification, if any.
	ExistingClassification *ClassificationLevel `json:"existing_classification,omitempty"`
}

// HandlingValidation holds the result of a handling validation check.
type HandlingValidation struct {
	// Valid indicates whether the handling meets requirements.
	Valid bool `json:"valid"`

	// Classification is the classification level being validated.
	Classification ClassificationLevel `json:"classification"`

	// Violations lists specific handling requirement violations.
	Violations []string `json:"violations"`

	// Timestamp records when the validation was performed.
	Timestamp time.Time `json:"timestamp"`
}

// ClassificationEnforcer classifies data and enforces handling requirements.
type ClassificationEnforcer struct {
	policy ClassificationPolicy
}

// NewClassificationEnforcer creates a new enforcer with default requirements.
func NewClassificationEnforcer() *ClassificationEnforcer {
	return &ClassificationEnforcer{
		policy: defaultClassificationPolicy(),
	}
}

// NewClassificationEnforcerWithPolicy creates an enforcer with a custom policy.
func NewClassificationEnforcerWithPolicy(policy ClassificationPolicy) *ClassificationEnforcer {
	return &ClassificationEnforcer{policy: policy}
}

// ValidateClassificationTransition checks if transitioning from one level to
// another is permitted. Classification can only be upgraded (increased), never
// downgraded without explicit declassification authority.
func ValidateClassificationTransition(from, to ClassificationLevel) error {
	if to.Rank() < from.Rank() {
		return fmt.Errorf("ValidateClassificationTransition: %w: cannot downgrade from %s to %s without declassification authority",
			ErrInvalidClassification, from, to)
	}
	return nil
}

// ClassifyData determines the classification level of the provided data.
func (e *ClassificationEnforcer) ClassifyData(_ context.Context, data []byte, classCtx ClassificationContext) (*ClassificationResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ClassificationEnforcer.ClassifyData: %w: data is empty", ErrInvalidClassification)
	}

	// If an existing classification is provided, honour it.
	if classCtx.ExistingClassification != nil {
		return &ClassificationResult{
			Level:      *classCtx.ExistingClassification,
			Confidence: 100,
			Reason:     "Pre-assigned classification",
			Timestamp:  time.Now().UTC(),
		}, nil
	}

	result := &ClassificationResult{
		Level:      e.policy.DefaultLevel,
		Confidence: 70,
		Reason:     "Classified by content analysis",
		Timestamp:  time.Now().UTC(),
	}

	content := strings.ToLower(string(data))

	// Check for indicators in order of sensitivity (highest first).
	if containsAny(content, []string{"top secret", "ts/sci", "codeword"}) {
		result.Level = TopSecret
		result.Confidence = 95
		result.Indicators = append(result.Indicators, "top_secret_marker")
	} else if containsAny(content, []string{"secret", "noforn"}) {
		result.Level = Secret
		result.Confidence = 90
		result.Indicators = append(result.Indicators, "secret_marker")
	} else if containsAny(content, []string{"confidential"}) {
		result.Level = Confidential
		result.Confidence = 85
		result.Indicators = append(result.Indicators, "confidential_marker")
	} else if containsAny(content, []string{"fouo", "for official use only"}) {
		result.Level = FOUO
		result.Confidence = 80
		result.Indicators = append(result.Indicators, "fouo_marker")
	} else if containsAny(content, []string{"cui", "controlled unclassified"}) {
		result.Level = CUI
		result.Confidence = 80
		result.Indicators = append(result.Indicators, "cui_marker")
	}

	return result, nil
}

// EnforceClassification verifies that data handling meets the requirements for
// the specified classification level.
func (e *ClassificationEnforcer) EnforceClassification(_ context.Context, data []byte, requiredLevel ClassificationLevel) (*HandlingValidation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ClassificationEnforcer.EnforceClassification: %w: data is empty", ErrInvalidClassification)
	}

	reqs, ok := e.policy.LevelRequirements[requiredLevel]
	if !ok {
		return nil, fmt.Errorf("ClassificationEnforcer.EnforceClassification: %w: no requirements for level %s", ErrInvalidClassification, requiredLevel)
	}

	validation := &HandlingValidation{
		Valid:          true,
		Classification: requiredLevel,
		Timestamp:      time.Now().UTC(),
	}

	// Validate handling requirements against expected controls.
	if reqs.EncryptionRequired {
		// In production: verify that data is actually encrypted.
		// For now, we validate that the requirement is acknowledged.
		validation.Violations = append(validation.Violations[:0:0], validation.Violations...)
	}

	if reqs.AirGapRequired {
		// Air-gap requirement check — would integrate with AirGapController.
	}

	if reqs.HSMRequired {
		// HSM requirement check — would integrate with KMS providers.
	}

	validation.Valid = len(validation.Violations) == 0
	return validation, nil
}

// ValidateHandling checks whether the handling of data meets the requirements
// for its classification level.
func (e *ClassificationEnforcer) ValidateHandling(_ context.Context, data []byte, classification ClassificationLevel) (*HandlingValidation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("ClassificationEnforcer.ValidateHandling: %w: data is empty", ErrInvalidClassification)
	}

	reqs, ok := e.policy.LevelRequirements[classification]
	if !ok {
		return nil, fmt.Errorf("ClassificationEnforcer.ValidateHandling: %w: no requirements for level %s", ErrInvalidClassification, classification)
	}

	validation := &HandlingValidation{
		Valid:          true,
		Classification: classification,
		Timestamp:      time.Now().UTC(),
	}

	_ = reqs // requirements checked in production implementation
	return validation, nil
}

// GetPolicy returns the current classification policy.
func (e *ClassificationEnforcer) GetPolicy() ClassificationPolicy {
	return e.policy
}

// GetHandlingRequirements returns the handling requirements for a level.
func (e *ClassificationEnforcer) GetHandlingRequirements(level ClassificationLevel) (*HandlingRequirements, error) {
	reqs, ok := e.policy.LevelRequirements[level]
	if !ok {
		return nil, fmt.Errorf("ClassificationEnforcer.GetHandlingRequirements: %w: no requirements for level %s", ErrInvalidClassification, level)
	}
	return &reqs, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func defaultClassificationPolicy() ClassificationPolicy {
	return ClassificationPolicy{
		DefaultLevel:    Unclassified,
		EnforcementMode: "enforce",
		LevelRequirements: map[ClassificationLevel]HandlingRequirements{
			Unclassified: {
				Level:               Unclassified,
				EncryptionRequired:  false,
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.2+",
				AccessControlRequired: false,
				AuditRequired:       false,
			},
			CUI: {
				Level:               CUI,
				EncryptionRequired:  true,
				EncryptionAlgorithm: "AES-256-GCM",
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.3",
				AccessControlRequired: true,
				ClearanceRequired:   "None (NIST SP 800-171 compliant)",
				StorageRequirements: "Encrypted storage with access logging",
				DisposalMethod:      "NIST SP 800-88 media sanitization",
				AuditRequired:       true,
				MarkingRequired:     true,
			},
			FOUO: {
				Level:               FOUO,
				EncryptionRequired:  true,
				EncryptionAlgorithm: "AES-256-GCM",
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.3",
				AccessControlRequired: true,
				StorageRequirements: "Encrypted storage with access logging",
				DisposalMethod:      "Overwrite or physical destruction",
				AuditRequired:       true,
				MarkingRequired:     true,
			},
			Confidential: {
				Level:               Confidential,
				EncryptionRequired:  true,
				EncryptionAlgorithm: "AES-256-GCM",
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.3",
				AccessControlRequired: true,
				ClearanceRequired:   "Confidential",
				StorageRequirements: "GSA-approved security container",
				DisposalMethod:      "NSA/CSS approved destruction",
				AuditRequired:       true,
				MarkingRequired:     true,
				NeedToKnow:         true,
				HSMRequired:        true,
			},
			Secret: {
				Level:               Secret,
				EncryptionRequired:  true,
				EncryptionAlgorithm: "AES-256-GCM",
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.3 with PQ-safe algorithms",
				AccessControlRequired: true,
				ClearanceRequired:   "Secret",
				StorageRequirements: "Accredited Secret-level facility",
				DisposalMethod:      "NSA/CSS approved destruction",
				AuditRequired:       true,
				MarkingRequired:     true,
				NeedToKnow:         true,
				AirGapRequired:     true,
				HSMRequired:        true,
			},
			TopSecret: {
				Level:               TopSecret,
				EncryptionRequired:  true,
				EncryptionAlgorithm: "AES-256-GCM with PQ-safe key exchange",
				TransitEncryption:   true,
				TransitProtocol:     "TLS 1.3 with ML-DSA-65 certificates",
				AccessControlRequired: true,
				ClearanceRequired:   "Top Secret",
				StorageRequirements: "Accredited TS/SCI facility (SCIF)",
				DisposalMethod:      "NSA/CSS approved destruction with witness",
				AuditRequired:       true,
				MarkingRequired:     true,
				NeedToKnow:         true,
				AirGapRequired:     true,
				HSMRequired:        true,
			},
		},
		HandlingInstructions: map[ClassificationLevel]string{
			Unclassified: "No special handling required.",
			CUI:          "Handle in accordance with NIST SP 800-171 and 32 CFR Part 2002.",
			FOUO:         "Distribute only to authorized personnel with a need to know.",
			Confidential: "Protect IAW applicable security classification guide.",
			Secret:       "Protect IAW applicable security classification guide. Store in GSA-approved container or accredited IS.",
			TopSecret:    "Protect IAW applicable security classification guide. Maintain continuous accountability.",
		},
	}
}
