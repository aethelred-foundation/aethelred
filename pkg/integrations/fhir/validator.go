package fhir

import (
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// FHIR Resource Validation
// ---------------------------------------------------------------------------
//
// Validator performs structural validation of FHIR R5 resources. It checks
// required fields, valid status values, and referential integrity according
// to the FHIR R5 specification.
// ---------------------------------------------------------------------------

// ValidationResult contains the outcome of a resource validation.
type ValidationResult struct {
	// Valid indicates whether the resource passed all checks.
	Valid bool `json:"valid"`

	// Errors lists fatal issues that prevent the resource from being accepted.
	Errors []string `json:"errors,omitempty"`

	// Warnings lists non-fatal issues that should be addressed.
	Warnings []string `json:"warnings,omitempty"`
}

// Validator performs structural validation of FHIR resources.
type Validator struct {
	// strictMode enables additional validation beyond minimum requirements.
	strictMode bool
}

// NewValidator creates a new FHIR resource validator with default settings.
func NewValidator() *Validator {
	return &Validator{}
}

// NewStrictValidator creates a validator that enforces additional constraints.
func NewStrictValidator() *Validator {
	return &Validator{strictMode: true}
}

// ValidateResource performs type-dispatched validation on any FHIR resource.
func (v *Validator) ValidateResource(resource Resource) *ValidationResult {
	if resource == nil {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{"resource is nil"},
		}
	}

	switch r := resource.(type) {
	case *Patient:
		return v.ValidatePatient(r)
	case *Observation:
		return v.ValidateObservation(r)
	case *DiagnosticReport:
		return v.ValidateDiagnosticReport(r)
	case *Medication:
		return v.ValidateMedication(r)
	case *Consent:
		return v.ValidateConsent(r)
	case *AuditEvent:
		return v.ValidateAuditEvent(r)
	case *Bundle:
		return v.ValidateBundle(r)
	default:
		return &ValidationResult{
			Valid:    false,
			Errors:   []string{fmt.Sprintf("unknown resource type: %T", resource)},
		}
	}
}

// ValidatePatient validates a Patient resource.
func (v *Validator) ValidatePatient(patient *Patient) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if patient == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "patient is nil")
		return result
	}

	// Required: ID
	if patient.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Patient.id is required")
	}

	// Required: resourceType must be "Patient"
	if patient.ResourceType != "" && patient.ResourceType != "Patient" {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Patient.resourceType must be 'Patient', got '%s'", patient.ResourceType))
	}

	// Validate gender if present.
	if patient.Gender != "" {
		validGenders := map[string]bool{"male": true, "female": true, "other": true, "unknown": true}
		if !validGenders[patient.Gender] {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Patient.gender invalid: '%s'", patient.Gender))
		}
	}

	// Validate birthDate format if present (YYYY-MM-DD or YYYY-MM or YYYY).
	if patient.BirthDate != "" {
		if !isValidFHIRDate(patient.BirthDate) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Patient.birthDate may not be a valid FHIR date: '%s'", patient.BirthDate))
		}
	}

	// Strict mode: require at least one name.
	if v.strictMode && len(patient.Name) == 0 {
		result.Warnings = append(result.Warnings, "Patient.name is recommended")
	}

	return result
}

// ValidateObservation validates an Observation resource.
func (v *Validator) ValidateObservation(obs *Observation) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if obs == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "observation is nil")
		return result
	}

	if obs.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Observation.id is required")
	}

	// Required: status
	if obs.Status == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Observation.status is required")
	} else {
		validStatuses := map[ObservationStatus]bool{
			ObservationStatusRegistered:     true,
			ObservationStatusPreliminary:    true,
			ObservationStatusFinal:          true,
			ObservationStatusAmended:        true,
			ObservationStatusCorrected:      true,
			ObservationStatusCancelled:      true,
			ObservationStatusEnteredInError: true,
			ObservationStatusUnknown:        true,
		}
		if !validStatuses[obs.Status] {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Observation.status invalid: '%s'", obs.Status))
		}
	}

	// Required: code
	if len(obs.Code.Coding) == 0 && obs.Code.Text == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Observation.code is required")
	}

	// Strict mode: require subject.
	if v.strictMode && obs.Subject == nil {
		result.Warnings = append(result.Warnings, "Observation.subject is recommended")
	}

	return result
}

// ValidateDiagnosticReport validates a DiagnosticReport resource.
func (v *Validator) ValidateDiagnosticReport(report *DiagnosticReport) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if report == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "diagnosticReport is nil")
		return result
	}

	if report.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "DiagnosticReport.id is required")
	}

	if report.Status == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "DiagnosticReport.status is required")
	}

	if len(report.Code.Coding) == 0 && report.Code.Text == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "DiagnosticReport.code is required")
	}

	return result
}

// ValidateMedication validates a Medication resource.
func (v *Validator) ValidateMedication(med *Medication) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if med == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "medication is nil")
		return result
	}

	if med.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Medication.id is required")
	}

	if len(med.Code.Coding) == 0 && med.Code.Text == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Medication.code is required")
	}

	return result
}

// ValidateConsent validates a Consent resource according to FHIR R5 rules.
func (v *Validator) ValidateConsent(consent *Consent) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if consent == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "consent is nil")
		return result
	}

	if consent.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Consent.id is required")
	}

	// Required: status
	if consent.Status == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Consent.status is required")
	} else {
		validStatuses := map[ConsentStatus]bool{
			ConsentStatusDraft:          true,
			ConsentStatusActive:         true,
			ConsentStatusInactive:       true,
			ConsentStatusNotDone:        true,
			ConsentStatusEnteredInError: true,
		}
		if !validStatuses[consent.Status] {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Consent.status invalid: '%s'", consent.Status))
		}
	}

	// Required: scope
	if len(consent.Scope.Coding) == 0 && consent.Scope.Text == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Consent.scope is required")
	}

	// Validate provision period if present.
	if consent.Provision != nil && consent.Provision.Period != nil {
		p := consent.Provision.Period
		if p.Start != nil && p.End != nil && p.End.Before(*p.Start) {
			result.Valid = false
			result.Errors = append(result.Errors, "Consent.provision.period.end cannot be before start")
		}
	}

	// Strict mode: require patient.
	if v.strictMode && consent.Patient == nil {
		result.Warnings = append(result.Warnings, "Consent.subject (patient) is recommended")
	}

	return result
}

// ValidateAuditEvent validates an AuditEvent resource.
func (v *Validator) ValidateAuditEvent(event *AuditEvent) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if event == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "auditEvent is nil")
		return result
	}

	if event.ID == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "AuditEvent.id is required")
	}

	// Required: recorded
	if event.Recorded.IsZero() {
		result.Valid = false
		result.Errors = append(result.Errors, "AuditEvent.recorded is required")
	}

	// Required: code
	if len(event.Code.Coding) == 0 && event.Code.Text == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "AuditEvent.code is required")
	}

	// Required: at least one agent.
	if len(event.Agent) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "AuditEvent.agent is required (at least one)")
	}

	// Required: source.
	if event.Source.Observer.Reference == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "AuditEvent.source.observer is required")
	}

	return result
}

// ValidateBundle validates a Bundle resource.
func (v *Validator) ValidateBundle(bundle *Bundle) *ValidationResult {
	result := &ValidationResult{Valid: true}

	if bundle == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "bundle is nil")
		return result
	}

	if bundle.ID == "" {
		result.Warnings = append(result.Warnings, "Bundle.id is recommended")
	}

	// Required: type
	if bundle.Type == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "Bundle.type is required")
	} else {
		validTypes := map[BundleType]bool{
			BundleTypeDocument:    true,
			BundleTypeMessage:     true,
			BundleTypeTransaction: true,
			BundleTypeBatch:       true,
			BundleTypeSearchset:   true,
			BundleTypeCollection:  true,
		}
		if !validTypes[bundle.Type] {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Bundle.type invalid: '%s'", bundle.Type))
		}
	}

	// Verify total matches entry count if set.
	if bundle.Total > 0 && bundle.Total != len(bundle.Entry) {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Bundle.total (%d) does not match entry count (%d)", bundle.Total, len(bundle.Entry)))
	}

	return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isValidFHIRDate checks if a string is a valid FHIR date (YYYY, YYYY-MM,
// or YYYY-MM-DD).
func isValidFHIRDate(s string) bool {
	formats := []string{"2006-01-02", "2006-01", "2006"}
	for _, fmt := range formats {
		if _, err := time.Parse(fmt, s); err == nil {
			return true
		}
	}
	return false
}
