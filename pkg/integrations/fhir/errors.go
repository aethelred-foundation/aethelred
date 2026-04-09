package fhir

import "errors"

// Sentinel errors for the FHIR integration package.
var (
	// ErrInvalidResource indicates a FHIR resource failed structural validation.
	ErrInvalidResource = errors.New("fhir: invalid resource")

	// ErrConsentRequired indicates that consent is required but not present.
	ErrConsentRequired = errors.New("fhir: consent required")

	// ErrConsentRevoked indicates the relevant consent has been revoked.
	ErrConsentRevoked = errors.New("fhir: consent revoked")

	// ErrSealFailed indicates a Digital Seal operation failed.
	ErrSealFailed = errors.New("fhir: seal operation failed")

	// ErrValidationFailed indicates resource validation did not pass.
	ErrValidationFailed = errors.New("fhir: validation failed")

	// ErrAuditFailed indicates an audit event generation or export failed.
	ErrAuditFailed = errors.New("fhir: audit operation failed")
)
