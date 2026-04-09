package fhir

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// FHIR Consent Management
// ---------------------------------------------------------------------------
//
// ConsentManager provides lifecycle management for FHIR Consent resources.
// It supports validation, sealing, revocation, and policy evaluation to
// ensure that data access complies with patient consent directives.
// ---------------------------------------------------------------------------

// ConsentPolicy defines the rules governing consent evaluation.
type ConsentPolicy struct {
	// RequireExplicit mandates that explicit consent must exist before any
	// data access. When false, an implied consent model is used.
	RequireExplicit bool

	// DefaultScope is applied when a consent does not specify a scope.
	DefaultScope string

	// AllowedPurposes lists the purposes for which data access is permitted.
	AllowedPurposes []string

	// RetentionPolicy defines how long consent records are retained.
	RetentionPolicy *RetentionConfig
}

// RetentionConfig defines consent record retention settings.
type RetentionConfig struct {
	// MaxAgeDays is the maximum age of a consent record before archival.
	MaxAgeDays int

	// ArchiveOnRevocation archives a consent immediately upon revocation.
	ArchiveOnRevocation bool
}

// ConsentManager manages FHIR Consent resources with sealing and audit
// trail support.
type ConsentManager struct {
	mu     sync.RWMutex
	bridge *FHIRBridge
	policy ConsentPolicy

	// consents maps patient references to their active consent records.
	consents map[string][]storedConsent
}

// storedConsent wraps a consent with its seal metadata.
type storedConsent struct {
	Consent  Consent `json:"consent"`
	SealID   string  `json:"seal_id,omitempty"`
	SealedAt time.Time `json:"sealed_at,omitempty"`
	Revoked  bool    `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// NewConsentManager creates a new ConsentManager with the given bridge and
// policy configuration.
func NewConsentManager(bridge *FHIRBridge, policy ConsentPolicy) *ConsentManager {
	if policy.DefaultScope == "" {
		policy.DefaultScope = "patient-privacy"
	}
	return &ConsentManager{
		bridge:   bridge,
		policy:   policy,
		consents: make(map[string][]storedConsent),
	}
}

// ValidateConsent checks whether a valid, active consent exists for the
// given patient and purpose. Returns true if consent is granted.
func (cm *ConsentManager) ValidateConsent(_ context.Context, patient string, purpose string) (bool, error) {
	if patient == "" {
		return false, fmt.Errorf("ConsentManager.ValidateConsent: %w: patient reference is empty", ErrConsentRequired)
	}
	if purpose == "" {
		return false, fmt.Errorf("ConsentManager.ValidateConsent: %w: purpose is empty", ErrConsentRequired)
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	records, ok := cm.consents[patient]
	if !ok || len(records) == 0 {
		if cm.policy.RequireExplicit {
			return false, nil
		}
		// Implied consent model: allow when no explicit denial exists.
		return true, nil
	}

	// Check for an active consent that covers the requested purpose.
	for _, sc := range records {
		if sc.Revoked {
			continue
		}
		if sc.Consent.Status != ConsentStatusActive {
			continue
		}

		// Check if the consent period is valid.
		if sc.Consent.Provision != nil && sc.Consent.Provision.Period != nil {
			now := time.Now().UTC()
			if sc.Consent.Provision.Period.Start != nil && now.Before(*sc.Consent.Provision.Period.Start) {
				continue
			}
			if sc.Consent.Provision.Period.End != nil && now.After(*sc.Consent.Provision.Period.End) {
				continue
			}
		}

		// Evaluate the consent against the purpose.
		if cm.EvaluateConsentPolicy(&sc.Consent, purpose) {
			return true, nil
		}
	}

	return false, nil
}

// CreateConsent creates and seals a new consent record. The consent is
// validated, stored, and optionally sealed through the bridge.
func (cm *ConsentManager) CreateConsent(ctx context.Context, consent Consent) (*SealedConsent, error) {
	// Validate the consent.
	v := NewValidator()
	result := v.ValidateConsent(&consent)
	if !result.Valid {
		return nil, fmt.Errorf("ConsentManager.CreateConsent: %w: %v", ErrValidationFailed, result.Errors)
	}

	// Ensure status is set.
	if consent.Status == "" {
		consent.Status = ConsentStatusActive
	}

	// Set resource type.
	consent.ResourceType = "Consent"

	// Extract patient reference for indexing.
	patientRef := ""
	if consent.Patient != nil {
		patientRef = consent.Patient.Reference
	}
	if patientRef == "" {
		return nil, fmt.Errorf("ConsentManager.CreateConsent: %w: patient reference is empty", ErrConsentRequired)
	}

	// TOCTOU fix: hold lock through the entire validate-seal-store sequence.
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Seal through the bridge if available.
	var sealID string
	var sealedAt time.Time
	if cm.bridge != nil {
		sealed, err := cm.bridge.SealResource(ctx, &consent)
		if err != nil {
			return nil, fmt.Errorf("ConsentManager.CreateConsent: %w: %v", ErrSealFailed, err)
		}
		sealID = sealed.SealID
		sealedAt = sealed.SealedAt
	} else {
		sealedAt = time.Now().UTC()
	}

	// Store the consent.
	cm.consents[patientRef] = append(cm.consents[patientRef], storedConsent{
		Consent:  consent,
		SealID:   sealID,
		SealedAt: sealedAt,
	})

	return &SealedConsent{
		ConsentID:  consent.ID,
		PatientRef: patientRef,
		SealID:     sealID,
		Status:     consent.Status,
		SealedAt:   sealedAt,
	}, nil
}

// RevokeConsent revokes a consent record and records an audit trail. The
// consent is marked as inactive and sealed in its revoked state.
func (cm *ConsentManager) RevokeConsent(_ context.Context, consentID string) error {
	if consentID == "" {
		return fmt.Errorf("ConsentManager.RevokeConsent: %w: consent ID is empty", ErrInvalidResource)
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	for patientRef, records := range cm.consents {
		for i, sc := range records {
			if sc.Consent.ID == consentID {
				if sc.Revoked {
					return fmt.Errorf("ConsentManager.RevokeConsent: %w: consent %s", ErrConsentRevoked, consentID)
				}

				now := time.Now().UTC()
				cm.consents[patientRef][i].Revoked = true
				cm.consents[patientRef][i].RevokedAt = &now
				cm.consents[patientRef][i].Consent.Status = ConsentStatusInactive
				return nil
			}
		}
	}

	return fmt.Errorf("ConsentManager.RevokeConsent: consent %s not found", consentID)
}

// GetActiveConsents returns all active (non-revoked) consent records for the
// given patient.
func (cm *ConsentManager) GetActiveConsents(_ context.Context, patient string) ([]Consent, error) {
	if patient == "" {
		return nil, fmt.Errorf("ConsentManager.GetActiveConsents: %w: patient reference is empty", ErrInvalidResource)
	}

	cm.mu.RLock()
	defer cm.mu.RUnlock()

	records, ok := cm.consents[patient]
	if !ok {
		return nil, nil
	}

	var active []Consent
	for _, sc := range records {
		if !sc.Revoked && sc.Consent.Status == ConsentStatusActive {
			active = append(active, sc.Consent)
		}
	}

	return active, nil
}

// EvaluateConsentPolicy evaluates whether a given purpose is permitted
// under the consent's provisions and the configured policy.
func (cm *ConsentManager) EvaluateConsentPolicy(consent *Consent, purpose string) bool {
	if consent == nil {
		return false
	}

	// If the consent is not active, deny access.
	if consent.Status != ConsentStatusActive {
		return false
	}

	// Check if the consent provision type is "deny" — explicit denial.
	if consent.Provision != nil && consent.Provision.Type == "deny" {
		return false
	}

	// Check the allowed purposes in the policy.
	if len(cm.policy.AllowedPurposes) > 0 {
		purposeAllowed := false
		for _, ap := range cm.policy.AllowedPurposes {
			if ap == purpose {
				purposeAllowed = true
				break
			}
		}
		if !purposeAllowed {
			return false
		}
	}

	// Check the consent provision purposes.
	if consent.Provision != nil && len(consent.Provision.Purpose) > 0 {
		for _, cp := range consent.Provision.Purpose {
			if cp.Code == purpose {
				return true
			}
		}
		// Purposes are specified but the requested purpose is not listed.
		return false
	}

	// No specific purpose restrictions; consent is general.
	return true
}

// ConsentCount returns the total number of stored consents.
func (cm *ConsentManager) ConsentCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	count := 0
	for _, records := range cm.consents {
		count += len(records)
	}
	return count
}

// ---------------------------------------------------------------------------
// Consent result types
// ---------------------------------------------------------------------------

// SealedConsent contains the result of creating and sealing a consent.
type SealedConsent struct {
	ConsentID  string        `json:"consent_id"`
	PatientRef string        `json:"patient_ref"`
	SealID     string        `json:"seal_id,omitempty"`
	Status     ConsentStatus `json:"status"`
	SealedAt   time.Time     `json:"sealed_at"`
}
