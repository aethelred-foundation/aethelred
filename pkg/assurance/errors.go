package assurance

import "errors"

// Sentinel errors for the assurance package. Use errors.Is() to check.
var (
	// ErrInvalidInput indicates that a function received an invalid argument.
	ErrInvalidInput = errors.New("invalid input")

	// ErrJobNotFound indicates that the requested computation job does not exist.
	ErrJobNotFound = errors.New("job not found")

	// ErrProviderUnavailable indicates that a required evidence provider is not available.
	ErrProviderUnavailable = errors.New("provider unavailable")

	// ErrEvidenceIncomplete indicates that collected evidence is insufficient.
	ErrEvidenceIncomplete = errors.New("evidence incomplete")

	// ErrVerificationFailed indicates that receipt verification did not pass.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrExportFailed indicates that an export operation could not be completed.
	ErrExportFailed = errors.New("export failed")

	// ErrMonitoringFailed indicates that continuous monitoring encountered an error.
	ErrMonitoringFailed = errors.New("monitoring failed")
)
