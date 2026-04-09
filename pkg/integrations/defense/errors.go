package defense

import "errors"

// Sentinel errors for the defense integration package.
var (
	// ErrInvalidClassification indicates an invalid classification level.
	ErrInvalidClassification = errors.New("defense: invalid classification")

	// ErrCMMCAssessmentFailed indicates a CMMC assessment operation failed.
	ErrCMMCAssessmentFailed = errors.New("defense: CMMC assessment failed")

	// ErrAirGapViolation indicates an air-gap requirement was violated.
	ErrAirGapViolation = errors.New("defense: air-gap violation")

	// ErrKMSFailed indicates a KMS/HSM key management operation failed.
	ErrKMSFailed = errors.New("defense: KMS operation failed")

	// ErrProcurementFailed indicates a procurement artifact operation failed.
	ErrProcurementFailed = errors.New("defense: procurement failed")

	// ErrInsufficientClearance indicates the personnel clearance is insufficient.
	ErrInsufficientClearance = errors.New("defense: insufficient clearance")
)
