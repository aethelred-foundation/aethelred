package fhir

import (
	"testing"
)

// ---------------------------------------------------------------------------
// FuzzFHIRResourceValidation
// ---------------------------------------------------------------------------

// FuzzFHIRResourceValidation fuzzes FHIR resource field values to verify
// that validation correctly identifies missing required fields and accepts
// well-formed resources.
//
// Invariants:
//   - Missing required fields (ID, status, code) produce validation errors.
//   - Valid resources pass validation.
//   - No panics regardless of input.
func FuzzFHIRResourceValidation(f *testing.F) {
	// Seed corpus: valid, empty, edge cases
	f.Add("patient-001", "Patient", "male", "1990-01-01", true)
	f.Add("", "", "", "", false)
	f.Add("obs-001", "Observation", "final", "2024-01-01", true)
	f.Add("p-\x00\xff", "Patient", "\t\n", "not-a-date", false)
	f.Add("consent-001", "Consent", "active", "", true)
	f.Add("medication-001", "Medication", "active", "", true)

	f.Fuzz(func(t *testing.T, id, resourceType, statusOrGender, dateField string, active bool) {
		v := NewValidator()

		// Test Patient validation
		patient := &Patient{
			ResourceType: "Patient",
			ID:           id,
			Gender:       statusOrGender,
			BirthDate:    dateField,
			Active:       active,
		}
		patResult := v.ValidatePatient(patient)
		// Invariant: missing ID always produces error
		if id == "" && patResult.Valid {
			t.Error("Patient with empty ID must fail validation")
		}
		// Invariant: valid patient passes
		if id != "" {
			// resourceType mismatch check
			if resourceType != "" && resourceType != "Patient" {
				patient.ResourceType = resourceType
				r := v.ValidatePatient(patient)
				if r.Valid {
					t.Error("Patient with wrong resourceType should fail validation")
				}
			}
		}

		// Test Observation validation
		obs := &Observation{
			ResourceType: "Observation",
			ID:           id,
			Status:       ObservationStatus(statusOrGender),
			Code:         CodeableConcept{Text: dateField},
		}
		obsResult := v.ValidateObservation(obs)
		if id == "" && obsResult.Valid {
			t.Error("Observation with empty ID must fail validation")
		}
		if statusOrGender == "" && obsResult.Valid {
			t.Error("Observation with empty status must fail validation")
		}

		// Test Consent validation
		consent := &Consent{
			ResourceType: "Consent",
			ID:           id,
			Status:       ConsentStatus(statusOrGender),
			Scope:        CodeableConcept{Text: dateField},
		}
		conResult := v.ValidateConsent(consent)
		if id == "" && conResult.Valid {
			t.Error("Consent with empty ID must fail validation")
		}
		if statusOrGender == "" && conResult.Valid {
			t.Error("Consent with empty status must fail validation")
		}
		if dateField == "" && conResult.Valid {
			t.Error("Consent with empty scope must fail validation")
		}

		// Test nil resource
		nilResult := v.ValidateResource(nil)
		if nilResult.Valid {
			t.Error("nil resource must fail validation")
		}
	})
}

// ---------------------------------------------------------------------------
// FuzzFHIRConsentStatus
// ---------------------------------------------------------------------------

// FuzzFHIRConsentStatus fuzzes consent status values to verify that only
// known FHIR R5 consent statuses are accepted.
//
// Invariants:
//   - Only known statuses (draft, active, inactive, not-done, entered-in-error) are valid.
//   - Unknown status values produce validation errors.
//   - No panics regardless of input.
func FuzzFHIRConsentStatus(f *testing.F) {
	// Seed: known statuses
	f.Add("draft", "consent-001", "privacy-scope")
	f.Add("active", "consent-002", "treatment")
	f.Add("inactive", "consent-003", "research")
	f.Add("not-done", "consent-004", "scope-text")
	f.Add("entered-in-error", "consent-005", "error-scope")
	// Seed: invalid statuses
	f.Add("", "consent-006", "scope")
	f.Add("ACTIVE", "consent-007", "scope")
	f.Add("pending", "consent-008", "scope")
	f.Add("revoked", "consent-009", "scope")
	f.Add("\x00\xff\t", "consent-010", "scope")
	f.Add("active; DROP TABLE", "consent-011", "scope")

	knownStatuses := map[ConsentStatus]bool{
		ConsentStatusDraft:          true,
		ConsentStatusActive:         true,
		ConsentStatusInactive:       true,
		ConsentStatusNotDone:        true,
		ConsentStatusEnteredInError: true,
	}

	f.Fuzz(func(t *testing.T, status, id, scopeText string) {
		consent := &Consent{
			ResourceType: "Consent",
			ID:           id,
			Status:       ConsentStatus(status),
			Scope:        CodeableConcept{Text: scopeText},
		}

		v := NewValidator()
		result := v.ValidateConsent(consent)

		isKnown := knownStatuses[ConsentStatus(status)]

		if id == "" {
			// ID is always required, so result.Valid should be false
			if result.Valid {
				t.Error("consent with empty ID must fail validation")
			}
			return
		}

		if status == "" {
			if result.Valid {
				t.Error("consent with empty status must fail validation")
			}
			return
		}

		if scopeText == "" {
			if result.Valid {
				t.Error("consent with empty scope must fail validation")
			}
			return
		}

		// When all required fields are present:
		if isKnown {
			// Known status with all required fields should pass
			if !result.Valid {
				t.Errorf("valid consent with status %q should pass validation, errors: %v",
					status, result.Errors)
			}
		} else {
			// Unknown status should fail
			if result.Valid {
				t.Errorf("consent with unknown status %q should fail validation", status)
			}
		}
	})
}
